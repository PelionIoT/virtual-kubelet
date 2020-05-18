#!/bin/bash

set -e
#set -x

if [ -z "$4" ]
then
    echo "Usage: generate-kubeconfigs.sh <SERVER_URI> <ACCOUNT_ID> <NUMBER> <OUTPUT_DIRECTORY>"

    exit 1
fi

export SERVER_URI=$1
export ACCOUNT_ID=$2
N=$3
OUT_DIR=$4

if [ ! -d "$OUT_DIR" ]; then
    echo "Output directory $OUT_DIR does not exist"

    exit 1
fi

while [ "$N" -gt 0 ]; do
    export DEVICE_ID="$(uuid | sed 's/-//g')"

    # Generate self-signed device certificate
    openssl req \
        -x509 \
        -nodes \
        -newkey rsa:2048 \
        -keyout /tmp/kubelet.key \
        -out /tmp/kubelet.crt \
        -subj "/C=US/ST=TX/L=$DEVICE_ID/O=my_o/OU=$ACCOUNT_ID/CN=$DEVICE_ID/emailAddress=email@example.com" \
        -days 365

    export CLIENT_CERT="$(cat /tmp/kubelet.crt | base64 -w0)"
    export CLIENT_KEY="$(cat /tmp/kubelet.key | base64 -w0)"
    echo "$(cat kubeconfig.yaml.tpl | envsubst)" > $OUT_DIR/$DEVICE_ID.kubeconfig
    N=$(( N - 1 ))
done
