apiVersion: v1
clusters:
- cluster:
    server: $SERVER_URI
  name: kaas
contexts:
- context:
    cluster: kaas
    user: $DEVICE_ID
  name: kaas
current-context: kaas
kind: Config
preferences: {}
users:
- name: $DEVICE_ID
  user:
    client-certificate-data: $CLIENT_CERT
    client-key-data: $CLIENT_KEY
