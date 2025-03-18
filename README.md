# synology-cert-updater
Automatically update Synology certificates stored as Kubernetes secrets.

## Overview

This tool triggers a job whenever a certificate stored as a Kubernetes secret is renewed. The most common approach is to generate certificates using Let's Encrypt via [Cert-Manager](https://cert-manager.io/).

## Deployment Options

### CronJob

The simplest method is to schedule a periodic CronJob. External logic can be added to check whether the certificate has changed before executing the update.

### Argo Events

A more efficient, event-driven approach is to use [Argo Events](https://argoproj.github.io/argo-events/). When a secret is updated, Argo can trigger a job to handle the certificate update automatically.

#### Considerations:

- If the certificate is stored in a different namespace, proper **RBAC permissions** must be assigned, or the certificate must be copied to the namespace where the job runs.
- I tested [Kubernetes Reflector](https://github.com/emberstack/kubernetes-reflector) to replicate secrets across multiple namespaces, but it resulted in multiple failing jobs.
- An alternative approach is [ClusterSecret](https://github.com/zakkg3/ClusterSecret), which allows sharing secrets across namespaces more reliably.

## Configuring the Secret

A Kubernetes secret is required to authenticate with the Synology NAS. Create it using the following command:

```sh
kubectl -n cert-manager create secret generic synology-credentials \
  --from-literal=username='<username>' \
  --from-literal=password='<password>'
```

## Environment Variables

The following global variables must be defined in the job:

```sh
"SYNOLOGY_URL": "https://host:5001",
"SYNOLOGY_USER": "username",
"SYNOLOGY_PASS": "password",
"SECRET_NAME": "",
"SECRET_NAMESPACE": "cert-manager",
"COMMON_NAME": "",
"KUBECONFIG_MODE": "local"
```

## Potential Improvements