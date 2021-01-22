#!/bin/bash

set -e
set -u

if [ -z "$API_HOST" ]; then
    echo "API_HOST must be set to target enviroment."
    echo "  Production example:     export API_HOST=\"https://api.us-east-1.mbedcloud.com\""
    echo "  OS2 example:            export API_HOST=\"https://api-os2.mbedcloudstaging.net\""
    echo "  Integration example:    export API_HOST=\"https://lab-api.mbedcloudintegration.net\""
    exit 1
fi
if [ -z "$ACCESS_KEY" ]; then
    echo "ACCESS_KEY must be set to an access key for your account"
    echo "  Example: export ACCESS_KEY=\"ak_2MDE3MmRkNDIwN2UwODIwM2JhNzA2ODMwMDAwMDAwMDA0176e387ab7f2242d8a8b6ae...\""
    exit 1
fi

if [ -z "${4:-""}" ]
then
    echo "Usage: generate-kubeconfigs.sh <SERVER_URI> <PREFIX> <NUMBER> <OUTPUT_DIRECTORY>"

    exit 1
fi

export SERVER_URI=$1
PREFIX=$2
N=$3
OUT_DIR=$4

if [ ! -d "$OUT_DIR" ]; then
    echo "Output directory $OUT_DIR does not exist"

    exit 1
fi

TMP=$(mktemp -d)
CA_DIR="$TMP/ca"
CA_UPLOAD_NAME="$PREFIX-ca"
SERVICE="bootstrap"
BOOTSTRAP_URL="$(curl -X GET -s -S --fail "$API_HOST/v3/server-credentials" -H "accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer $ACCESS_KEY" | jq -r -e ".bootstrap.url")"
JOB_MAX="${JOB_MAX:-100}"

# Make bootstrap CA
echo "Making bootstrap CA"
mkdir "$CA_DIR"
(
cd "$CA_DIR"
openssl ecparam -out CA_private.pem -name prime256v1 -genkey
(echo '[req]'; echo 'distinguished_name=dn'; echo 'prompt=no'; echo '[dn]'; echo 'CN=CA'; echo '[ext]'; echo 'basicConstraints=CA:TRUE') > ca.cnf
openssl req -key CA_private.pem -new -sha256 -x509 -days 12775 -out CA_cert.pem -config ca.cnf -extensions ext
)

# If a certificate with the same name exists delete it so the upload doesn't fail
echo "Checking for conflicting CA"
if CERT_ID_OLD="$(curl -X GET -s -S --fail "$API_HOST/v3/trusted-certificates?name__eq=$CA_UPLOAD_NAME"  -H "Authorization: Bearer $ACCESS_KEY" | jq -e -r ".data[0].id")"; then
    echo "Deleting conflicting CA \"$CERT_ID_OLD\""
    curl -X DELETE -s -S --fail "$API_HOST/v3/trusted-certificates/$CERT_ID_OLD" -H "Authorization: Bearer $ACCESS_KEY"
fi

# Upload bootstrap CA
echo "Uploading bootstrap CA"
CA_CERT_DATA="$(cat "$CA_DIR/CA_cert.pem")"
POST_DATA="$(jq -n --arg ca_cert_name "$CA_UPLOAD_NAME" --arg ca_cert_data "$CA_CERT_DATA" --arg service "$SERVICE" '{"name": $ca_cert_name, "certificate": $ca_cert_data, "service": $service}')"
RESULT="$(curl -X POST -s -S --fail "$API_HOST/v3/trusted-certificates" -H "Authorization: Bearer $ACCESS_KEY" -H "content-type: application/json" -d "$POST_DATA")"
CERT_ID=$(echo "$RESULT" | jq -e -r ".id")

# Reusable code to run jobs in parallel
job_init() {
    JOB_NAMES=()                # Names of each job
    JOB_PIDS=()                 # PIDS of each job
    JOB_ERRORS=()               # sparse list of non-zero return codes
    JOB_MAX="${JOB_MAX:-20}"    # Number of jobs to run in parallel, default 20
    JOB_POS_NEXT_=0  # internal
    JOB_POS_WAIT_=0  # internal
}
job_wait_limit_() {
    local MAX_JOBS=$1
    while [ $(( JOB_POS_NEXT_ - JOB_POS_WAIT_ )) -gt $MAX_JOBS ]; do
        wait "${JOB_PIDS[$JOB_POS_WAIT_]}" || JOB_ERRORS[$JOB_POS_WAIT_]="$?"
        JOB_POS_WAIT_=$(( JOB_POS_WAIT_ + 1 ))
    done
}
job_add() {
    local NAME="$1"
    local PID="$2"
    JOB_NAMES[$JOB_POS_NEXT_]=$NAME
    JOB_PIDS[$JOB_POS_NEXT_]=$PID
    JOB_POS_NEXT_=$(( JOB_POS_NEXT_ + 1 ))
    job_wait_limit_ $(( JOB_MAX - 1 ))
}
job_wait_all() {
    job_wait_limit_ 0
}

# Generate certificates (do bootstrap in the background)
job_init
while [ "$N" -gt 0 ]; do
    ENDPOINT_NAME="$PREFIX-$N"
    BOOTSTRAP_CERT_FILE="$TMP/$ENDPOINT_NAME-bsCert.pem"
    BOOTSTRAP_KEY_FILE="$TMP/$ENDPOINT_NAME-bsKey.pem"
    KUBE_CERT_FILE="$TMP/$ENDPOINT_NAME-kubelet.crt"
    KUBE_KEY_FILE="$TMP/$ENDPOINT_NAME-kubelet.key"

    # Generate bootstrap certificates
    openssl ecparam -out "$BOOTSTRAP_KEY_FILE" -name prime256v1 -genkey
    openssl req -key "$BOOTSTRAP_KEY_FILE" -new -sha256 -out "$BOOTSTRAP_CERT_FILE.tmp" -subj "/CN=$ENDPOINT_NAME"
    openssl x509 -req -in "$BOOTSTRAP_CERT_FILE.tmp" -sha256 -out "$BOOTSTRAP_CERT_FILE" -CA "$CA_DIR/CA_cert.pem" -CAkey "$CA_DIR/CA_private.pem" -CAcreateserial -days 3650
    rm "$BOOTSTRAP_CERT_FILE.tmp"

    # Bootstrap in the background
    (
    RETRIES_MAX=5
    RETRIES=0
    until lwm2m-bootstrapper --mode bootstrap  \
    --coap-cert "$BOOTSTRAP_CERT_FILE" --coap-key "$BOOTSTRAP_KEY_FILE" --coap-url "$BOOTSTRAP_URL" \
    --dump-cert "$KUBE_CERT_FILE" --dump-key "$KUBE_KEY_FILE" > /dev/null 2> /dev/null
    do
        if [ "$RETRIES" -ge "$RETRIES_MAX" ]; then
            exit "$RETRIES"
        fi
        RETRIES=$(( RETRIES + 1 ))
    done

    export CLIENT_CERT="$(cat "$KUBE_CERT_FILE" | base64 -w0)"
    export CLIENT_KEY="$(cat "$KUBE_KEY_FILE" | base64 -w0)"
    echo "$(cat kubeconfig.yaml.tpl | envsubst)" > $OUT_DIR/$ENDPOINT_NAME.kubeconfig
    exit "$RETRIES"
    )&
    job_add "$ENDPOINT_NAME" "$!"

    N=$(( N - 1 ))
done
job_wait_all

# Print any errors that occurred
echo "Certificates created, ${#JOB_ERRORS[@]} errors occurred"
for I in "${!JOB_ERRORS[@]}"; do
    echo "  Error generating certificate for ${JOB_NAMES[$I]}: returned ${JOB_ERRORS[$I]}"
done

# Delete uploaded CA and temp files
curl -X DELETE -s -S --fail "$API_HOST/v3/trusted-certificates/$CERT_ID" -H "Authorization: Bearer $ACCESS_KEY"
rm -r "$TMP"

echo "Generating configs completed successfully"
