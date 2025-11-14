# Webhook Certificate Management with cert-controller

This document explains how Breakglass uses the Open Policy Agent's `cert-controller` for automatic webhook certificate generation and rotation.

## Overview

The Breakglass validating webhooks require TLS certificates to communicate securely with the Kubernetes API server. The `cert-controller` library provides an automated solution for:

1. **Generating** self-signed CA and server certificates on first deployment
2. **Storing** certificates in a Kubernetes Secret (`webhook-certs`)
3. **Injecting** the CA certificate into the ValidatingWebhookConfiguration
4. **Rotating** certificates before they expire
5. **Monitoring** certificate validity and automatically regenerating if needed

## Architecture

### Components

1. **cert-controller/rotator** (in cmd/main.go)
   - Runs as a controller-runtime Reconciler
   - Manages certificate lifecycle
   - Watches the webhook-certs secret
   - Patches the ValidatingWebhookConfiguration with the CA bundle

2. **webhook-certs Secret** (system/webhook-certs)
   - Stores the CA certificate, server certificate, and private key
   - Created and managed automatically by cert-controller
   - Mounted as a volume into the Breakglass pod

3. **ValidatingWebhookConfiguration** (config/webhook/manifests.yaml)
   - Annotated with `cert-controller.breakglass.io/inject-ca-from: "system/webhook-certs"`
   - CA bundle automatically populated by cert-controller
   - No manual certificate management needed

## Configuration

### Environment Variables

- **ENABLE_WEBHOOK_MANAGER** (default: "true")
  - Controls whether the controller-runtime manager starts
  - Must be true for cert-controller to function

- **ENABLE_CERT_ROTATION** (default: "true")
  - Controls whether certificate rotation is enabled
  - Set to "false" to disable automatic certificate management (not recommended)

- **POD_NAMESPACE** (default: "system")
  - Kubernetes namespace where the Breakglass pod runs
  - Used to construct DNS names for the certificate

### Certificate Parameters

The CertRotator is configured with the following:

```go
CertRotator{
    SecretKey:             "system/webhook-certs"          // Where certs are stored
    CertDir:               "/tmp/k8s-webhook-server/..."   // Mount path in pod
    CAName:                "breakglass-webhook-ca"         // CA certificate name
    CAOrganization:        "Deutsche Telekom, Breakglass"  // Certificate organization
    DNSName:               "webhook-service.system.svc"    // Primary DNS name
    ExtraDNSNames: [       // Additional valid DNS names
        "webhook-service.system",
        "webhook-service",
    ]
    RestartOnSecretRefresh: false                          // Don't restart pod on cert update
}
```

### DNS Names

The certificate is valid for the following DNS names:

- `webhook-service` (internal pod name)
- `webhook-service.system` (with namespace)
- `webhook-service.system.svc` (fully qualified service DNS)

The DNS names are constructed from:

- Service name: `webhook-service` (hardcoded)
- Namespace: From `POD_NAMESPACE` environment variable

If your service is in a different namespace or has a different name, you must update:

1. The `DNSName` and `ExtraDNSNames` in cmd/main.go
2. The service name in config/deployment/service.yaml

## Deployment

### Volume Mounts

The Breakglass deployment mounts the certificate volume:

```yaml
volumeMounts:
- mountPath: /tmp/k8s-webhook-server/serving-certs
  name: webhook-certs
  readOnly: true

volumes:
- name: webhook-certs
  secret:
    secretName: webhook-certs
    optional: true  # Pod starts even if secret doesn't exist yet
```

### RBAC Permissions

The `manager` ServiceAccount needs permissions to:

- **Read/Write/Patch Secrets**: For managing the webhook-certs secret
- **Patch ValidatingWebhookConfiguration**: For injecting the CA bundle

These permissions are defined in:

```
config/rbac/webhook_cert_rotator_role.yaml
```

Required rules (following least privilege principle):

```yaml
# Create the webhook-certs secret on initial setup
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create"]

# Update and patch the specific webhook-certs secret
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["webhook-certs"]
  verbs: ["get", "update", "patch"]

# Patch ValidatingWebhookConfiguration to inject CA bundle
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["validatingwebhookconfigurations"]
  resourceNames: ["validating-webhook-configuration"]
  verbs: ["get", "patch"]
```

**Note**: This follows the principle of least privilege by:
- Only allowing operations on the specific `webhook-certs` secret
- Only allowing `patch` (not `update`) on webhook configurations after initial setup
- Not granting permissions to mutating webhooks if not used
- Not allowing listing or watching across all secrets

## Certificate Lifecycle

### Initial Setup (First Deployment)

1. Breakglass pod starts
2. cert-controller receives the `setupFinished` channel
3. It generates a self-signed CA certificate and server certificate
4. Stores both in the `system/webhook-certs` Secret
5. Patches `ValidatingWebhookConfiguration` with the CA bundle
6. Closes the `setupFinished` channel to signal readiness
7. Webhooks become available to the API server

### Rotation Check

The cert-controller periodically (every 12 hours by default):

1. Reads the current certificate from the secret
2. Checks if it's still valid (uses lookahead interval: ~1 month before expiration)
3. If rotation needed:
   - Generates new certificates
   - Updates the secret
   - Patches the ValidatingWebhookConfiguration
   - Updates any other registered webhooks

### On Pod Restart

- The webhook-certs volume is mounted immediately
- No need to wait for certificate generation
- Webhooks are available with the existing certificate
- If the secret is missing, the pod starts anyway (optional mount)

## Troubleshooting

### Webhooks Not Working

Check if the webhook-certs secret exists:

```bash
kubectl get secret -n system webhook-certs
kubectl describe secret -n system webhook-certs
```

Check the ValidatingWebhookConfiguration has the CA bundle:

```bash
kubectl get validatingwebhookconfigurations validating-webhook-configuration -o yaml | grep -A 5 caBundle
```

Check logs for cert-controller errors:

```bash
kubectl logs -n system deployment/manager | grep -i cert
```

### Certificate Expired

The cert-controller should automatically rotate certificates before expiration. If certificates have expired:

1. Delete the secret: `kubectl delete secret -n system webhook-certs`
2. Restart the Breakglass pod
3. cert-controller will generate new certificates

### Customizing Certificate Duration

Edit cmd/main.go to customize:

```go
certRotator := &rotator.CertRotator{
    // ... other fields ...
    CaCertDuration: 10 * 365 * 24 * time.Hour,      // 10 years
    ServerCertDuration: 365 * 24 * time.Hour,       // 1 year
    RotationCheckFrequency: 12 * time.Hour,         // Check every 12 hours
    LookaheadInterval: 168 * time.Hour,             // Rotate ~1 month before expiry
}
```

## Integration with Other Certificate Management Solutions

If you prefer to use external certificate management (e.g., cert-manager):

1. Set `ENABLE_CERT_ROTATION=false`
2. Manually create and manage the `webhook-certs` Secret
3. Ensure the secret contains:
   - `tls.crt`: Server certificate
   - `tls.key`: Private key
4. Manually patch the ValidatingWebhookConfiguration with the CA bundle

Alternatively, use cert-manager to create a Certificate resource and sync it to the secret.

## References

- [cert-controller GitHub](https://github.com/open-policy-agent/cert-controller)
- [cert-controller Documentation](https://github.com/open-policy-agent/cert-controller/blob/master/README.md)
- [Kubernetes ValidatingWebhookConfiguration](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
