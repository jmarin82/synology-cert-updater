# synology-cert-updater
Update synology certificates generated as secrets in kubernetes.

# Secret
Debemos de crear un secret para conectar a la NAS synology

kubectl -n cert-manager create secret generic synology-credentials \
  --from-literal=username='<username>' \
  --from-literal=password='<password>'

# Environment variables

Estas son las variables globales que definiremos en el job:

"SYNOLOGY_URL": "https://host:5001",
"SYNOLOGY_USER": "username",
"SYNOLOGY_PASS": "password",
"SECRET_NAME": "",
"SECRET_NAMESPACE": "cert-manager",
"COMMON_NAME": "",
"KUBECONFIG_MODE": "local"

