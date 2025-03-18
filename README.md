# synology-cert-updater
Update synology certificates generated as secrets in kubernetes.
La idea es generar un job cuando se renueve un certificado que se almacenará como secret en nuestro cluster de kubernetes. 
Lo más habitual es generar certificados de letsencrypt con cert-manager. 

Existen múltiples opciones:

## Cronjob
 La opción más básica es ejecutar un cronjob periódico. Se podría agregar una lógica externa para verificar antes si ha habido algún cambio en el certificado. 

## Argo Events

Esta opción me parece muy elegante al estar basada en eventos. La idea es que ante un evento originado por el cambio del secret, Argo genere un job con la tarea. Hay que tener en cuenta que si el certificado reside en otro namespace habrá que asignar permisos RBAC o bien copiar el certificado al namespace donde se ejecuta el job. 
He probado a usar replicator para copiar el certificado en varios namespaces pero ha desencadenado en multitud de jobs que terminan en error. 

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

# Mejoras
