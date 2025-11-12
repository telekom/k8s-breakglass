# Quick Start Guide

Get breakglass running in 5 minutes.

## Prerequisites

- Kubernetes 1.24+ (hub cluster to run breakglass)
- kubectl configured to access hub cluster
- OIDC provider (Keycloak, Azure AD, etc.) for authentication
- Network access from tenant clusters to hub cluster

## 1. Prepare Configuration

Copy the example config:

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml` with your settings:

```yaml
server:
  listenAddress: :8080

authorizationserver:
  url: https://keycloak.example.com
  jwksEndpoint: "realms/master/protocol/openid-connect/certs"

frontend:
  identityProviderName: "production-idp"  # REQUIRED
  baseURL: https://breakglass.example.com

mail:
  host: smtp.example.com
  port: 587
  senderAddress: breakglass@example.com

kubernetes:
  context: ""
  oidcPrefixes:
    - "oidc:"
```

## 2. Create IdentityProvider Resource

**This is REQUIRED** - Breakglass will not start without it.

Create `identity-provider.yaml`:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: production-idp
spec:
  primary: true
  oidc:
    authority: "https://keycloak.example.com/realms/master"
    clientID: "breakglass-ui"
```

Deploy to hub cluster:

```bash
kubectl apply -f identity-provider.yaml -n breakglass-system
```

Verify:

```bash
kubectl get identityproviders
```

## 3. Deploy to Hub Cluster

Update deployment configuration:

```bash
# Edit to use your config
sed -i 's/your-config/config.yaml/' config/default/config.yaml
```

Deploy:

```bash
make deploy
```

Verify deployment:

```bash
kubectl get pods -n breakglass-system
kubectl get crd | grep breakglass
```

## 4. Create Your First Escalation Policy

Create a file `escalation-policy.yaml`:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: sre-production-access
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    clusters: ["prod-cluster"]
    groups: ["site-reliability-engineers"]
  approvers:
    groups: ["security-team"]
  maxValidFor: "2h"
  idleTimeout: "1h"
```

Deploy:

```bash
kubectl apply -f escalation-policy.yaml
```

## 5. Configure Tenant Cluster

On the tenant cluster that needs breakglass authorization:

Create webhook kubeconfig:

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: breakglass
    cluster:
      server: https://breakglass.example.com/api/breakglass/webhook/authorize/prod-cluster
      certificate-authority-data: <BASE64_CA_CERT>
users:
  - name: kube-apiserver
    user:
      token: <SECURE_TOKEN>
contexts:
  - name: webhook
    context:
      cluster: breakglass
      user: kube-apiserver
current-context: webhook
```

Update API server authorization config (`/etc/kubernetes/authorization-config.yaml`):

```yaml
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
  - type: Node
    name: node
  - type: RBAC
    name: rbac
  - type: Webhook
    name: breakglass
    webhook:
      timeout: 3s
      authorizedTTL: 30s
      unauthorizedTTL: 30s
      subjectAccessReviewVersion: v1
      failurePolicy: Deny
      connectionInfo:
        type: KubeConfigFile
        kubeConfigFile: /etc/kubernetes/breakglass-webhook-kubeconfig.yaml
      matchConditions:
        - expression: "'system:authenticated' in request.groups"
        - expression: "!request.user.startsWith('system:')"
```

Restart kube-apiserver:

```bash
# For kubeadm clusters
ssh node systemctl restart kubelet
```

## 5. Connect Tenant Cluster to Hub

Create a secret with tenant cluster admin kubeconfig on hub:

```bash
kubectl create secret generic prod-cluster-admin \
  --from-file=kubeconfig=/path/to/tenant/kubeconfig.yaml \
  -n default
```

Create ClusterConfig resource:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: prod-cluster
spec:
  clusterID: prod-cluster
  environment: prod
  kubeconfigSecretRef:
    name: prod-cluster-admin
    namespace: default
  qps: 100
  burst: 200
```

Deploy:

```bash
kubectl apply -f clusterconfig.yaml
```

Verify connection:

```bash
kubectl get clusterconfig prod-cluster
kubectl describe clusterconfig prod-cluster
```

## 6. Test It Works

### Request Escalation

```bash
# Get your token
TOKEN=$(oidc-token)

# Request access
curl -X POST https://breakglass.example.com/api/breakglass/request \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cluster": "prod-cluster",
    "user": "user@example.com",
    "group": "cluster-admin"
  }'
```

### Approve Request

As an approver:

```bash
curl -X POST https://breakglass.example.com/api/breakglass/approve/user@example.com \
  -H "Authorization: Bearer $APPROVER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cluster": "prod-cluster",
    "group": "cluster-admin"
  }'
```

### Use Elevated Access

```bash
# Now your kubectl requests will be authorized by breakglass
kubectl get pods --all-namespaces
```

## 7. Access the Web UI

Open browser to: `https://breakglass.example.com`

- Login with your OIDC credentials
- View available escalations
- Request access
- Approvers can approve/deny requests

## What's Next?

- [Learn about escalation policies](./breakglass-escalation.md)
- [Configure deny policies](./deny-policy.md)
- [Set up webhook properly](./webhook-setup.md)
- [Review troubleshooting](./troubleshooting.md)

## Common Next Steps

### Add More Clusters

1. Create admin secret for each cluster
2. Create `ClusterConfig` for each cluster
3. Configure webhook on each cluster
4. Update `BreakglassEscalation` to include new clusters

### Set Up Notifications

Configure email service in `config.yaml`:

```yaml
mail:
  host: smtp.example.com
  port: 587
  username: breakglass
  password: <secure-password>
  fromAddress: breakglass@example.com
```

Approvers receive email notifications for new requests.

### Enable TLS

Generate certificates and update config:

```yaml
server:
  tlsCertFile: /etc/breakglass/tls.crt
  tlsKeyFile: /etc/breakglass/tls.key
```

### Add Deny Policies

Restrict certain users from accessing sensitive resources:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: protect-kube-system
spec:
  rules:
    - verbs: ["*"]
      apiGroups: ["*"]
      resources: ["*"]
      namespaces: ["kube-system"]
  precedence: 10
```

## Troubleshooting

See [Troubleshooting Guide](./troubleshooting.md) for common issues and solutions.

Quick checks:

```bash
# Check all resources created
kubectl get breakglassescalation,breakglasssession,clusterconfig,denypolicy

# Check controller health
kubectl get deployment -n breakglass-system
kubectl logs -n breakglass-system deployment/breakglass-controller

# Verify webhook configuration
kubectl get clusterconfig
kubectl describe clusterconfig prod-cluster
```

## Security Notes

- Always use TLS for webhook communication
- Rotate authentication tokens regularly
- Use strong OIDC provider configurations
- Review escalation policies periodically
- Monitor all access attempts in logs

## Getting Help

- Check [Troubleshooting Guide](./troubleshooting.md)
- Review [API Reference](./api-reference.md)
- See [Webhook Setup](./webhook-setup.md) for detailed webhook configuration
