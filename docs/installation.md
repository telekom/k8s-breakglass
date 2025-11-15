# Installation Guide

Complete step-by-step installation instructions for breakglass.

## System Requirements

- Kubernetes 1.24+ hub cluster for breakglass deployment
- Kubernetes 1.24+ tenant clusters (for breakglass authorization)
- kubectl configured with hub cluster access
- OIDC provider (Keycloak, Azure AD, Okta, etc.)
- Container registry access (Docker, Container Registry, etc.)
- DNS accessible to both hub and tenant clusters

## Step 1: Prepare Hub Cluster

Verify hub cluster access:

```bash
kubectl cluster-info
kubectl get nodes
```

Create namespace:

```bash
kubectl create namespace breakglass-system
```

## Step 2: Configure Breakglass

Create `config.yaml` based on `config.example.yaml`:

```bash
cp config.example.yaml config.yaml
```

Edit with your environment:

```yaml
server:
  listenAddress: :8080
  tlsCertFile: /etc/breakglass/tls/tls.crt
  tlsKeyFile: /etc/breakglass/tls/tls.key

authorizationserver:
  url: https://keycloak.example.com/realms/master
  jwksEndpoint: "protocol/openid-connect/certs"

frontend:
  identityProviderName: production-idp  # REQUIRED - name of IdentityProvider CR
  baseURL: https://breakglass.example.com
  brandingName: "Das SCHIFF Breakglass"

mail:
  host: smtp.example.com
  port: 587
  username: breakglass
  password: <secure-password>
  senderAddress: breakglass-noreply@example.com

kubernetes:
  context: ""
  oidcPrefixes:
    - "oidc:"
```

**Important:** The `identityProviderName` field in `frontend` section is **REQUIRED**. It must reference a valid IdentityProvider resource that will be created in the next step.

For complete configuration options, see [Configuration Reference](./configuration-reference.md).

## Step 3: Create IdentityProvider Resource

**IdentityProvider is MANDATORY** for Breakglass operation. Create the IdentityProvider resource in the hub cluster.

### 3a. Create OIDC-only Configuration (Minimal)

```yaml
# identity-provider.yaml
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

Apply to the hub cluster:

```bash
kubectl apply -f identity-provider.yaml -n breakglass-system
```

Verify:

```bash
kubectl get identityproviders
```

### 3b. Create OIDC with Keycloak Group Sync (Advanced)

For group-based authorization:

```yaml
# identity-provider.yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: production-idp
spec:
  primary: true
  oidc:
    authority: "https://keycloak.example.com/realms/master"
    clientID: "breakglass-ui"
  
  # Optional: Group synchronization
  groupSyncProvider: Keycloak
  keycloak:
    baseURL: "https://keycloak.example.com"
    realm: "master"
    clientID: "breakglass-service-account"
    clientSecretRef:
      name: keycloak-service-account
      namespace: breakglass-system
      key: clientSecret
    cacheTTL: "10m"
    requestTimeout: "10s"
```

Create Keycloak service account secret:

```bash
kubectl create secret generic keycloak-service-account \
  -n breakglass-system \
  --from-literal=clientSecret=<service-account-password>
```

Apply IdentityProvider:

```bash
kubectl apply -f identity-provider.yaml
```

**Note:** The Keycloak service account should have **view-users** and **view-groups** permissions only (no admin rights).

## Step 4: Create Secrets

Create TLS secret:

```bash
kubectl create secret tls breakglass-tls \
  -n breakglass-system \
  --cert=/path/to/cert.pem \
  --key=/path/to/key.pem
```

Create config secret:

```bash
kubectl create secret generic breakglass-config \
  -n breakglass-system \
  --from-file=config.yaml=config.yaml
```

## Step 5: Build and Push Image

Build image (use OSS flavour):

```bash
docker build -t breakglass:v1.0.0 .
```

Push to registry:

```bash
docker tag breakglass:v1.0.0 myregistry.example.com/breakglass:v1.0.0
docker push myregistry.example.com/breakglass:v1.0.0
```

## Step 6: Deploy to Hub Cluster

Update deployment manifests with your image:

```bash
sed -i 's|breakglass:latest|myregistry.example.com/breakglass:v1.0.0|g' \
  config/deployment/app.yaml
```

Deploy:

```bash
kubectl apply -f config/crd/
kubectl apply -f config/rbac/
kubectl apply -f config/deployment/
```

Verify deployment:

```bash
kubectl get pods -n breakglass-system
kubectl get crd | grep breakglass
```

## Step 7: Expose Breakglass Service

Create Ingress for external access:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: breakglass
  namespace: breakglass-system
spec:
  tls:
    - hosts:
        - breakglass.example.com
      secretName: breakglass-tls
  rules:
    - host: breakglass.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: breakglass
                port:
                  number: 8080
```

Apply:

```bash
kubectl apply -f ingress.yaml
```

Verify DNS resolution:

```bash
nslookup breakglass.example.com
```

## Step 8: Configure Tenant Clusters

For each tenant cluster:

### 7a. Create Webhook Kubeconfig

Create `/etc/kubernetes/breakglass-webhook-kubeconfig.yaml`:

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: breakglass
    cluster:
      server: https://breakglass.example.com/api/breakglass/webhook/authorize/<cluster-name>
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

### 7b. Create Authorization Config

Create `/etc/kubernetes/authorization-config.yaml`:

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
        - expression: "!('system:serviceaccounts' in request.groups)"
```

### 7c. Update API Server

Update kube-apiserver manifest to use authorization config:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    command:
    - kube-apiserver
    - --authorization-config=/etc/kubernetes/authorization-config.yaml
    volumeMounts:
    - name: authz-config
      mountPath: /etc/kubernetes/authorization-config.yaml
      readOnly: true
    - name: authz-kubeconfig
      mountPath: /etc/kubernetes/breakglass-webhook-kubeconfig.yaml
      readOnly: true
  volumes:
  - name: authz-config
    hostPath:
      path: /etc/kubernetes/authorization-config.yaml
  - name: authz-kubeconfig
    hostPath:
      path: /etc/kubernetes/breakglass-webhook-kubeconfig.yaml
```

Restart API server:

```bash
ssh tenant-cluster-node \
  sudo systemctl restart kubelet
```

Verify webhook is active:

```bash
# Should not error about webhook
kubectl auth can-i get pods --as=test-user
```

## Step 8: Connect Tenant Clusters to Hub

Create admin secret for each tenant:

```bash
kubectl create secret generic <cluster-name>-admin \
  --from-file=kubeconfig=/path/to/tenant/admin.kubeconfig \
  -n default
```

Create ClusterConfig:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: prod-cluster-1
spec:
  clusterID: prod-cluster-1
  environment: prod
  kubeconfigSecretRef:
    name: prod-cluster-1-admin
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
kubectl get clusterconfig prod-cluster-1
kubectl describe clusterconfig prod-cluster-1
```

## Step 9: Create Escalation Policies

Create escalation policy:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: sre-emergency-access
spec:
  escalatedGroup: cluster-admin
  allowed:
    clusters: [prod-cluster-1, prod-cluster-2]
    groups: [site-reliability-engineers]
  approvers:
    groups: [security-team]
  maxValidFor: 2h
  idleTimeout: 1h
```

Deploy:

```bash
kubectl apply -f escalation.yaml
```

## Step 10: Test Installation

Request access:

```bash
TOKEN=$(oidc-token)  # Get OIDC token

curl -X POST https://breakglass.example.com/api/breakglass/request \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cluster": "prod-cluster-1",
    "user": "user@example.com",
    "group": "cluster-admin"
  }'
```

Approve request (as approver):

```bash
curl -X POST https://breakglass.example.com/api/breakglass/approve/user@example.com \
  -H "Authorization: Bearer $APPROVER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cluster": "prod-cluster-1",
    "group": "cluster-admin"
  }'
```

Test authorization on tenant cluster:

```bash
# Should now be allowed if session is active
kubectl get pods --all-namespaces
```

## Step 11: Verify and Secure

Verify all pods running:

```bash
kubectl get pods -n breakglass-system
```

Check logs for errors:

```bash
kubectl logs -n breakglass-system deployment/breakglass-controller
```

Secure OIDC client:

- Use strong client secrets
- Enable HTTPS only
- Restrict redirect URIs
- Rotate credentials regularly

Backup configuration:

```bash
kubectl get secrets,configmaps -n breakglass-system -o yaml > backup.yaml
```

## Post-Installation Tasks

1. **Configure monitoring** - Set up alerts for pod failures, high resource usage
2. **Enable audit logging** - Configure Kubernetes audit for all breakglass requests
3. **Review network policies** - Restrict access between hub and tenant clusters
4. **Schedule backups** - Backup secrets and custom resources regularly
5. **Document approval workflows** - Create runbooks for approvers
6. **Train users** - Ensure users know how to request access
7. **Regular reviews** - Periodically audit escalation policies

## Uninstalling Breakglass

```bash
# Delete all custom resources
kubectl delete breakglassescalation,breakglasssession,clusterconfig,denypolicy --all

# Delete deployment
kubectl delete namespace breakglass-system

# On tenant clusters, remove webhook config:
# 1. Remove authorization-config.yaml
# 2. Remove webhook kubeconfig
# 3. Restart kube-apiserver
```

## Controller Configuration Flags

The breakglass controller supports 40+ configuration flags for customizing deployment behavior. All flags are optional and have sensible defaults.

### Quick Flag Reference

| Flag | Default | Purpose |
|------|---------|---------|
| `--enable-leader-election` | `true` | Enable Kubernetes-native leader election for multi-replica deployments |
| `--enable-frontend` | `true` | Enable web UI endpoints |
| `--enable-api` | `true` | Enable REST API endpoints |
| `--enable-cleanup` | `true` | Enable background session cleanup routine |
| `--enable-webhooks` | `true` | Enable validating webhooks for CRDs |
| `--webhook-bind-address` | `0.0.0.0:9443` | Address for webhook server |
| `--metrics-bind-address` | `0.0.0.0:8081` | Address for Prometheus metrics endpoint |
| `--health-probe-bind-address` | `:8082` | Address for health probes (liveness/readiness) |
| `--config-path` | `./config.yaml` | Path to configuration file |
| `--pod-namespace` | `default` | Pod's namespace (used for event recording) |

### Setting Flags

Flags can be set via:

1. **Command-line arguments**:
```bash
breakglass-controller \
  --enable-leader-election=true \
  --webhook-bind-address=0.0.0.0:9443 \
  --config-path=/etc/breakglass/config.yaml
```

2. **Environment variables**:
```bash
export ENABLE_LEADER_ELECTION=true
export WEBHOOK_BIND_ADDRESS=0.0.0.0:9443
export BREAKGLASS_CONFIG_PATH=/etc/breakglass/config.yaml
breakglass-controller
```

3. **Kubernetes deployment**:
```yaml
containers:
- name: controller
  image: breakglass:latest
  args:
    - --enable-leader-election=true
    - --enable-frontend=true
    - --enable-api=true
    - --enable-cleanup=true
    - --enable-webhooks=true
    - --config-path=/etc/breakglass/config.yaml
    - --pod-namespace=breakglass-system
```

### Common Configurations

**Single Instance (Development)**:
```bash
breakglass-controller \
  --enable-leader-election=false \
  --enable-frontend=true \
  --enable-api=true \
  --enable-cleanup=true \
  --enable-webhooks=true
```

**Multi-Replica (Production)**:
```bash
breakglass-controller \
  --enable-leader-election=true \
  --enable-frontend=true \
  --enable-api=true \
  --enable-cleanup=true \
  --enable-webhooks=true \
  --pod-namespace=breakglass-system
```

**Webhook-Only Instance**:
```bash
breakglass-controller \
  --enable-frontend=false \
  --enable-api=false \
  --enable-cleanup=false \
  --enable-webhooks=true \
  --webhook-bind-address=0.0.0.0:9443
```

**API-Only Instance**:
```bash
breakglass-controller \
  --enable-frontend=true \
  --enable-api=true \
  --enable-cleanup=false \
  --enable-webhooks=false
```

For complete flag documentation, see [CLI Flags Reference](./cli-flags-reference.md).

## Leader Election and Scaling

For multi-replica deployments, leader election is **enabled by default** (`--enable-leader-election=true`):

- ✅ Automatically coordinates background loops across replicas
- ✅ Only leader runs cleanup, status updates, and config validation
- ✅ Automatic failover when leader crashes
- ✅ Uses Kubernetes Lease API (no external dependencies)

See [Scaling and Leader Election](./scaling-and-leader-election.md) for detailed information about:
- How leader election works
- Multi-replica deployment patterns
- Troubleshooting leadership issues
- Disabling leader election for single-instance deployments

## Troubleshooting Installation

See [Troubleshooting Guide](./troubleshooting.md) for common issues.

Quick verification:

```bash
# Check hub cluster
kubectl get all -n breakglass-system
kubectl get crd | grep breakglass

# Check tenant cluster webhook
journalctl -u kubelet | grep "webhook"

# Test API connectivity
curl -k https://breakglass.example.com/api/breakglass/health

# Test OIDC
curl https://keycloak.example.com/realms/master/.well-known/openid-configuration
```

## Getting Help

- [Quick Start Guide](./quickstart.md) - Fast 5-minute setup
- [Troubleshooting Guide](./troubleshooting.md) - Common issues
- [Webhook Setup](./webhook-setup.md) - Detailed webhook configuration
- [API Reference](./api-reference.md) - API endpoints
