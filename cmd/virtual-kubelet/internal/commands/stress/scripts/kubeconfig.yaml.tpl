apiVersion: v1
clusters:
- cluster:
    server: $SERVER_URI
  name: kaas
contexts:
- context:
    cluster: kaas
    user: kubelet
  name: kaas
current-context: kaas
kind: Config
preferences: {}
users:
- name: kubelet
  user:
    client-certificate-data: $CLIENT_CERT
    client-key-data: $CLIENT_KEY
