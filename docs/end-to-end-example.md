# End-to-End Example: Complete Breakglass Deployment

This guide walks through a complete, production-ready breakglass deployment scenario from scratch, including all CRDs, configurations, and operational workflows.

## Scenario Overview

**Company:** ExampleCorp
**Goal:** Enable SREs to request temporary cluster-admin access to production clusters with:
- Security team approval required
- Maximum 2-hour sessions
- Full audit trail
- Email notifications
- Multiple identity providers (corporate Azure AD + contractor Keycloak)

**Architecture:**
```
┌─────────────────────────────────────────────────────────────────┐
│                         Hub Cluster                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Breakglass Controller                   │   │
│  │  • API Server (port 8080)                               │   │
│  │  • Webhook Server (authorization decisions)              │   │
│  │  • Frontend UI                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   Prod-EU-1      │    │   Prod-US-1      │    │   Staging        │
│  (tenant cluster)│    │  (tenant cluster)│    │  (tenant cluster)│
└──────────────────┘    └──────────────────┘    └──────────────────┘
```

## Prerequisites

- Kubernetes 1.24+ clusters (1 hub, N tenants)
- kubectl access to hub cluster
- OIDC providers configured (Azure AD, Keycloak, etc.)
- SMTP server for email notifications
- TLS certificates for webhook communication

## Step 1: Install Breakglass Controller

### 1.1 Create Namespace

```bash
kubectl create namespace breakglass-system
```

### 1.2 Create Configuration ConfigMap

```yaml
# config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: breakglass-config
  namespace: breakglass-system
data:
  config.yaml: |
    server:
      listenAddress: :8080
    
    frontend:
      baseURL: https://breakglass.examplecorp.com
      brandingName: "ExampleCorp Breakglass"
    
    kubernetes:
      context: ""
      oidcPrefixes:
        - "https://login.microsoftonline.com/"
        - "https://keycloak.examplecorp.com/"
```

```bash
kubectl apply -f config.yaml
```

### 1.3 Deploy via Helm or Kustomize

```bash
# Using Helm
helm install breakglass charts/escalation-config \
  --namespace breakglass-system \
  --set image.tag=latest

# Or using kustomize
kubectl apply -k config/default
```

## Step 2: Configure Identity Providers

### 2.1 Primary IdP - Azure AD (Corporate Users)

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: azure-ad-corporate
  namespace: breakglass-system
spec:
  displayName: "ExampleCorp Azure AD"
  primary: true
  oidc:
    authority: "https://login.microsoftonline.com/tenant-id/v2.0"
    clientID: "breakglass-app-id"
    scopes:
      - openid
      - profile
      - email
    userIdentifierClaim: "preferred_username"
  # Optional: Restrict to specific domains
  allowedDomains:
    - "examplecorp.com"
```

### 2.2 Secondary IdP - Keycloak (Contractors)

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: keycloak-contractors
  namespace: breakglass-system
spec:
  displayName: "Contractor Portal"
  primary: false
  oidc:
    authority: "https://keycloak.examplecorp.com/realms/contractors"
    clientID: "breakglass-contractors"
    scopes:
      - openid
      - profile
      - email
    # Use Keycloak for group membership resolution
    keycloak:
      baseURL: "https://keycloak.examplecorp.com"
      realm: "contractors"
      clientID: "breakglass-admin"
      clientSecretRef:
        name: keycloak-admin-secret
        namespace: breakglass-system
        key: client-secret
```

### 2.3 Create Keycloak Secret

```bash
kubectl create secret generic keycloak-admin-secret \
  --namespace breakglass-system \
  --from-literal=client-secret="your-keycloak-client-secret"
```

### 2.4 Apply Identity Providers

```bash
kubectl apply -f azure-ad-corporate.yaml
kubectl apply -f keycloak-contractors.yaml

# Verify
kubectl get identityproviders -n breakglass-system
```

## Step 3: Configure Mail Provider

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: MailProvider
metadata:
  name: examplecorp-smtp
  namespace: breakglass-system
spec:
  displayName: "ExampleCorp Mail"
  default: true
  smtp:
    host: smtp.examplecorp.com
    port: 587
    username: breakglass-notifications@examplecorp.com
    passwordRef:
      name: smtp-credentials
      namespace: breakglass-system
      key: password
    starttls: true
  sender:
    address: breakglass-notifications@examplecorp.com
    name: "ExampleCorp Breakglass System"
  # Optional: Test email on provider creation
  healthCheck:
    enabled: true
    testRecipient: "breakglass-admin@examplecorp.com"
```

```bash
# Create SMTP secret
kubectl create secret generic smtp-credentials \
  --namespace breakglass-system \
  --from-literal=password="your-smtp-password"

# Apply mail provider
kubectl apply -f mail-provider.yaml
```

## Step 4: Connect Tenant Clusters

### 4.1 Generate Kubeconfig for Hub → Tenant Access

For each tenant cluster, create a service account and kubeconfig:

```bash
# On tenant cluster
TENANT_CLUSTER="prod-eu-1"

# Create service account
kubectl create serviceaccount breakglass-controller -n kube-system

# Create cluster role binding
kubectl create clusterrolebinding breakglass-controller \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:breakglass-controller

# Get token (Kubernetes 1.24+)
TOKEN=$(kubectl create token breakglass-controller -n kube-system --duration=8760h)

# Get cluster CA and API server
CA=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
SERVER=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.server}')

# Create kubeconfig
cat > ${TENANT_CLUSTER}-kubeconfig.yaml <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ${CA}
    server: ${SERVER}
  name: ${TENANT_CLUSTER}
users:
- name: breakglass-controller
  user:
    token: ${TOKEN}
contexts:
- context:
    cluster: ${TENANT_CLUSTER}
    user: breakglass-controller
  name: ${TENANT_CLUSTER}
current-context: ${TENANT_CLUSTER}
EOF
```

### 4.2 Create ClusterConfig on Hub

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: prod-eu-1
  namespace: breakglass-system
spec:
  clusterID: prod-eu-1
  displayName: "Production EU (Frankfurt)"
  kubeconfigRef:
    name: prod-eu-1-kubeconfig
    namespace: breakglass-system
    key: kubeconfig
  # Optional: Custom webhook URL if not using default
  webhookEndpoint: "https://breakglass.examplecorp.com/api/breakglass/webhook/authorize/prod-eu-1"
  # Optional: Health check settings
  healthCheck:
    enabled: true
    intervalSeconds: 60
```

```bash
# Create kubeconfig secret on hub cluster
kubectl create secret generic prod-eu-1-kubeconfig \
  --namespace breakglass-system \
  --from-file=kubeconfig=prod-eu-1-kubeconfig.yaml

# Apply ClusterConfig
kubectl apply -f cluster-config.yaml
```

### 4.3 Configure Tenant Cluster Authorization Webhook

On the tenant cluster, configure the API server to use breakglass as an authorization webhook:

```yaml
# /etc/kubernetes/authorization-config.yaml (API server)
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
      timeout: 5s
      failOpen: false
      subjectAccessReviewVersion: v1
      matchConditionSubjectAccessReviewVersion: v1
      connectionInfo:
        type: KubeConfigFile
        kubeConfigFile: /etc/kubernetes/breakglass-webhook.kubeconfig
```

```yaml
# /etc/kubernetes/breakglass-webhook.kubeconfig
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://breakglass.examplecorp.com/api/breakglass/webhook/authorize/prod-eu-1
    certificate-authority-data: <BASE64_CA_CERT>
  name: breakglass
users:
- name: kube-apiserver
  user:
    # Token is optional - can use mTLS instead
    token: <WEBHOOK_TOKEN>
contexts:
- context:
    cluster: breakglass
    user: kube-apiserver
  name: breakglass
current-context: breakglass
```

Restart API server to apply changes.

## Step 5: Create Escalation Policies

### 5.1 SRE Production Access

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: sre-production-access
  namespace: breakglass-system
spec:
  # Target group to grant
  escalatedGroup: "cluster-admin"
  
  # Who can request (must match OIDC groups)
  allowed:
    # Clusters this policy applies to
    clusters:
      - "prod-eu-1"
      - "prod-us-1"
    # Groups allowed to request access
    groups:
      - "sre-team"
      - "platform-engineering"
    # Optional: specific users
    # users: []
  
  # Who must approve (cannot include requester)
  approvers:
    groups:
      - "security-team"
      - "sre-leads"
    # Require at least 1 approval
    minRequired: 1
    # Optional: require approvers from multiple groups
    # requireApprovalFromEachGroup: true
  
  # Session constraints
  maxValidFor: "2h"        # Maximum session duration
  defaultValidFor: "1h"    # Default if not specified
  
  # Approval settings
  approvalRequired: true
  # autoApprove: false     # Never auto-approve production access
  
  # Request metadata
  requestReason:
    mandatory: true
    minLength: 20
    placeholderText: "Describe the incident/issue and what access is needed"
  
  # Optional: Scheduled sessions
  # allowScheduled: true
  # maxScheduleAhead: "168h"  # Up to 1 week in advance
  
  # Optional: Pod security overrides for this escalation
  # podSecurityOverrides:
  #   allowPrivileged: true
  #   riskScoreThreshold: 80
```

### 5.2 Staging Access (Less Restrictive)

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: dev-staging-access
  namespace: breakglass-system
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    clusters:
      - "staging"
    groups:
      - "developers"
      - "sre-team"
  approvers:
    # Self-approval allowed for staging
    selfApproval: true
    # Or: auto-approve during business hours
    # autoApprove: true
  maxValidFor: "8h"
  defaultValidFor: "4h"
  approvalRequired: false
  requestReason:
    mandatory: false
```

### 5.3 Apply Escalation Policies

```bash
kubectl apply -f sre-production-access.yaml
kubectl apply -f dev-staging-access.yaml

# Verify
kubectl get breakglassescalations -n breakglass-system
```

## Step 6: Create Deny Policies (Optional)

Restrict what users can do even with elevated access:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: protect-critical-namespaces
  namespace: breakglass-system
spec:
  # Apply to all clusters
  clusters:
    - "*"
  
  # Block dangerous operations on critical namespaces
  rules:
    - verbs: ["delete", "deletecollection"]
      resources: ["namespaces"]
      resourceNames:
        - "kube-system"
        - "kube-public"
        - "istio-system"
        - "cert-manager"
    
    - verbs: ["delete", "patch", "update"]
      apiGroups: [""]
      resources: ["secrets"]
      namespaces:
        - "kube-system"
      # Exception for specific escalation
      # exemptEscalations:
      #   - "emergency-access"
  
  # Pod security rules
  podSecurityRules:
    - action: "deny"
      matchConditions:
        hostNetwork: true
        hostPID: true
      message: "Host network/PID access is denied"
    
    - action: "warn"
      matchConditions:
        privileged: true
      message: "Privileged containers are logged for audit"
```

```bash
kubectl apply -f deny-policy.yaml
```

## Step 7: Configure Audit Logging (Optional)

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: AuditConfig
metadata:
  name: production-audit
  namespace: breakglass-system
spec:
  enabled: true
  
  # Kafka sink for SIEM integration
  sinks:
    - type: kafka
      name: security-siem
      kafka:
        brokers:
          - "kafka-1.examplecorp.com:9092"
          - "kafka-2.examplecorp.com:9092"
        topic: "breakglass-audit-events"
        sasl:
          enabled: true
          mechanism: "SCRAM-SHA-512"
          username: "breakglass-producer"
          passwordRef:
            name: kafka-credentials
            namespace: breakglass-system
            key: password
        tls:
          enabled: true
          insecureSkipVerify: false
    
    # Webhook for real-time alerting
    - type: webhook
      name: slack-alerts
      webhook:
        url: "https://hooks.slack.com/services/xxx/yyy/zzz"
        headers:
          Content-Type: "application/json"
        # Filter to only critical events
        eventFilter:
          eventTypes:
            - "session.created"
            - "session.approved"
            - "session.rejected"
            - "session.expired"
```

```bash
kubectl create secret generic kafka-credentials \
  --namespace breakglass-system \
  --from-literal=password="kafka-password"

kubectl apply -f audit-config.yaml
```

## Step 8: Test the Complete Flow

### 8.1 User Requests Access

1. User navigates to `https://breakglass.examplecorp.com`
2. Authenticates via Azure AD
3. Selects cluster: "Production EU (Frankfurt)"
4. Selects escalation: "sre-production-access"
5. Enters reason: "Investigating memory leak in payment-service pod"
6. Submits request

### 8.2 Approver Workflow

1. Security team member receives email notification
2. Reviews request in UI or via link in email
3. Approves or rejects with optional comment

### 8.3 Using the Session

Once approved, the user's OIDC identity is authorized for the granted group:

```bash
# User's normal kubectl config (with OIDC credentials)
kubectl --context=prod-eu-1 get pods -A  # Works!
kubectl --context=prod-eu-1 exec -it payment-service-xxx -- /bin/sh  # Works!
```

### 8.4 Session Expiry

- Session expires after `maxValidFor` (2 hours)
- User and approvers receive expiry notification
- All access is immediately revoked

## Step 9: Monitor and Operate

### 9.1 View Active Sessions

```bash
kubectl get breakglasssessions -n breakglass-system
kubectl get breakglasssessions -n breakglass-system -o wide
```

### 9.2 Prometheus Metrics

Key metrics to monitor:

```promql
# Active sessions by cluster
breakglass_sessions_active{cluster="prod-eu-1"}

# Session approval rate
rate(breakglass_session_approved_total[1h]) / rate(breakglass_session_created_total[1h])

# Webhook latency
histogram_quantile(0.99, breakglass_webhook_sar_duration_seconds_bucket)

# Denied requests
increase(breakglass_webhook_sar_denied_total[1h])
```

### 9.3 Troubleshooting

```bash
# Check controller logs
kubectl logs -n breakglass-system -l app=breakglass -f

# Check IdentityProvider status
kubectl describe identityprovider azure-ad-corporate -n breakglass-system

# Check ClusterConfig connectivity
kubectl describe clusterconfig prod-eu-1 -n breakglass-system

# Test webhook manually
curl -X POST https://breakglass.examplecorp.com/api/breakglass/webhook/authorize/prod-eu-1 \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview",...}'
```

## Complete Resource Summary

| Resource | Count | Purpose |
|----------|-------|---------|
| IdentityProvider | 2 | Azure AD + Keycloak |
| MailProvider | 1 | SMTP notifications |
| ClusterConfig | 3 | Hub + 2 tenants |
| BreakglassEscalation | 2 | Prod + Staging policies |
| DenyPolicy | 1 | Critical namespace protection |
| AuditConfig | 1 | Kafka + Slack audit |

## Next Steps

- [Advanced Features](./advanced-features.md) - Multi-IDP, domain restrictions, scheduled sessions
- [Debug Sessions](./debug-session.md) - kubectl debug integration
- [Security Best Practices](./security-best-practices.md) - Hardening guide
- [Metrics](./metrics.md) - Complete metrics reference
- [Troubleshooting](./troubleshooting.md) - Common issues

## Appendix: Complete YAML Bundle

For a single-file deployment, see [config/samples/complete-example.yaml](../config/samples/complete-example.yaml).
