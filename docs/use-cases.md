# Breakglass Use Cases

This guide covers real-world use cases collected from teams using Breakglass and provides concrete configuration examples for each scenario.

## Table of Contents

- [Pod Shell Access (kubectl exec)](#pod-shell-access-kubectl-exec)
- [Pod Restart and Rollout](#pod-restart-and-rollout)
- [Scaling Workloads](#scaling-workloads)
- [Resource Deletion](#resource-deletion)
- [Debug Tool Pods](#debug-tool-pods)
- [TCP Dump and Network Debugging](#tcp-dump-and-network-debugging)
- [M2M Automated Access](#m2m-automated-access)
- [Self-Service Debugging During BIS](#self-service-debugging-during-bis)

---

## Pod Shell Access (kubectl exec)

**Use Case:** Teams need shell access to running pods for:
- Running diagnostic commands
- Checking routing configurations
- Generating test alarms
- Executing troubleshooting scripts
- Inspecting container contents

### Configuration Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: pod-shell-access
spec:
  escalatedGroup: "pod-exec-access"
  description: "Shell access to application pods for troubleshooting"
  allowed:
    clusters: ["prod-cluster-1", "staging-cluster"]
    groups: ["developers", "operations"]
  approvers:
    groups: ["team-leads"]
    users: ["oncall@example.com"]
  maxValidFor: "2h"
  idleTimeout: "30m"
  requestReason:
    mandatory: true
    description: "Ticket ID and purpose for pod access"
```

### Required RBAC (on target cluster)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-exec-access
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
```

### Pod Security Considerations

If you want to control access to privileged pods, use a DenyPolicy:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: restrict-privileged-exec
spec:
  podSecurityRules:
    riskFactors:
      privilegedContainer: 100
      hostNetwork: 50
      hostPID: 75
    thresholds:
      - maxScore: 49
        action: allow
      - maxScore: 100
        action: deny
        reason: "Exec into privileged pods requires SRE escalation"
    exemptions:
      namespaces:
        patterns: ["kube-system"]
```

### Usage

```bash
# Request access
curl -X POST https://breakglass.example.com/api/breakglass/request \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"cluster": "prod-cluster-1", "group": "pod-exec-access", "reason": "INC-1234: Investigating connection timeout"}'

# After approval, exec into pod
kubectl exec -it my-pod -- /bin/bash
```

---

## Pod Restart and Rollout

**Use Case:** Teams need to restart pods for:
- Refreshing secrets/certificates
- Clearing stuck/hanging states  
- Applying ConfigMap changes
- Resolving "Verklemmungszustände" (deadlock states)

### Configuration Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: workload-restart
spec:
  escalatedGroup: "workload-restart"
  description: "Restart deployments and statefulsets"
  allowed:
    clusters: ["prod-cluster-1", "prod-cluster-2"]
    groups: ["application-owners", "sre"]
  approvers:
    groups: ["sre"]
    users: ["oncall@example.com"]
  # For quick pod restarts, consider shorter approval timeout
  approvalTimeout: "15m"
  maxValidFor: "1h"
  idleTimeout: "30m"
```

### Required RBAC (on target cluster)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: workload-restart
rules:
# Pod restart via delete
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "delete"]
# Rollout restart
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets"]
  verbs: ["get", "list", "patch"]
# Scale to 0 and back (alternative restart method)
- apiGroups: ["apps"]
  resources: ["deployments/scale", "statefulsets/scale"]
  verbs: ["get", "patch"]
```

### Self-Approval Option

For trusted teams who should be able to restart their own pods without waiting for approval:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: self-service-restart
spec:
  escalatedGroup: "workload-restart"
  allowed:
    clusters: ["dev-cluster", "staging-cluster"]
    groups: ["application-owners"]
  # Same group can approve - effectively self-approval
  approvers:
    groups: ["application-owners"]
  # Or explicitly allow self-approval
  blockSelfApproval: false
  maxValidFor: "2h"
```

### Usage

```bash
# Rollout restart (recommended)
kubectl rollout restart deployment/my-app

# Delete specific pod (controller will recreate)
kubectl delete pod my-app-xyz-abc

# Scale to 0 and back
kubectl scale deployment/my-app --replicas=0
kubectl scale deployment/my-app --replicas=3
```

---

## Scaling Workloads

**Use Case:** Emergency scaling for:
- Shutting down traffic instantly during incidents
- Scaling up during load spikes
- Maintenance windows

### Configuration Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: workload-scaling
spec:
  escalatedGroup: "workload-scale"
  description: "Scale deployments and statefulsets"
  allowed:
    clusters: ["prod-cluster-1", "prod-cluster-2"]
    groups: ["operations", "sre"]
  approvers:
    groups: ["sre-leads"]
  maxValidFor: "4h"
  requestReason:
    mandatory: true
    description: "Incident ticket and scaling justification"
```

### Required RBAC (on target cluster)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: workload-scale
rules:
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "replicasets"]
  verbs: ["get", "list", "patch", "update"]
- apiGroups: ["apps"]
  resources: ["deployments/scale", "statefulsets/scale", "replicasets/scale"]
  verbs: ["get", "patch", "update"]
# Optional: HPA management
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "patch", "update"]
```

### Usage

```bash
# Scale to zero (stop traffic)
kubectl scale deployment/my-app --replicas=0

# Scale up
kubectl scale deployment/my-app --replicas=10

# Patch via JSON (alternative)
kubectl patch deployment/my-app -p '{"spec":{"replicas":5}}'
```

---

## Resource Deletion

**Use Case:** Manual cleanup for:
- Deleting stuck HelmReleases
- Removing orphaned pods
- Cleaning up namespaces
- Deleting corrupted secrets

### Configuration Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: resource-cleanup
spec:
  escalatedGroup: "resource-cleanup"
  description: "Delete resources for incident cleanup"
  allowed:
    clusters: ["prod-cluster-1"]
    groups: ["sre", "platform-team"]
  approvers:
    groups: ["sre-leads", "security-team"]
  # Require approval - delete is destructive
  maxValidFor: "1h"
  requestReason:
    mandatory: true
    description: "Incident ticket and resources to delete"
  approvalReason:
    mandatory: true
    description: "Confirmation of deletion necessity"
```

### Required RBAC (on target cluster)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: resource-cleanup
rules:
# Pods (including force delete)
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "delete", "deletecollection"]
# HelmReleases (Flux)
- apiGroups: ["helm.toolkit.fluxcd.io"]
  resources: ["helmreleases"]
  verbs: ["get", "list", "delete", "patch"]
# Secrets
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "delete"]
# Namespaces (with care!)
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list", "delete"]
# ConfigMaps
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "delete"]
```

### DenyPolicy Protection

Protect critical resources from accidental deletion:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: protect-critical-resources
spec:
  rules:
    # Never delete these namespaces
    - verbs: ["delete"]
      apiGroups: [""]
      resources: ["namespaces"]
      resourceNames: ["kube-system", "kube-node-lease", "default"]
    # Protect database secrets
    - verbs: ["delete"]
      apiGroups: [""]
      resources: ["secrets"]
      resourceNames: ["database-credentials", "tls-certs"]
  precedence: 100  # High precedence = always evaluated
```

### Usage

```bash
# Delete pod
kubectl delete pod stuck-pod --force --grace-period=0

# Delete HelmRelease
kubectl delete helmrelease my-app -n my-namespace

# Delete namespace (with caution!)
kubectl delete namespace orphaned-namespace
```

---

## Debug Tool Pods

**Use Case:** Teams deploy dedicated debug pods with extra tools for:
- Network connectivity tests (curl, nc, openssl, snmpwalk)
- Certificate validation
- Firewall verification
- API testing from within the cluster

### Option 1: Using Debug Sessions (Recommended)

Debug Sessions allow deploying controlled debug pods without granting broader RBAC:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: network-debug-tools
spec:
  podSpec:
    containers:
    - name: debug
      image: nicolaka/netshoot:latest  # or your approved debug image
      command: ["/bin/sh", "-c", "sleep infinity"]
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
    restartPolicy: Never
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: network-debugging
spec:
  mode: workload
  workloadType: Deployment
  podTemplateRef: "network-debug-tools"
  allowed:
    clusters: ["prod-cluster-1"]
    groups: ["operations", "developers"]
  approvers:
    groups: ["sre"]
  constraints:
    maxDuration: "4h"
    defaultDuration: "1h"
```

### Option 2: Using kubectl-debug Mode

For ephemeral debugging directly into running pods without deploying new workloads:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: ephemeral-pod-debug
spec:
  mode: kubectl-debug
  kubectlDebug:
    ephemeralContainers:
      enabled: true
      allowedNamespaces: ["app-*", "services-*"]
      deniedNamespaces: ["kube-system"]
      allowedImages: ["busybox:*", "nicolaka/netshoot:*"]
    podCopy:
      enabled: true
      ttl: "1h"
  allowed:
    clusters: ["prod-cluster-1"]
    groups: ["developers", "sre"]
  approvers:
    groups: ["sre-leads"]
  constraints:
    maxDuration: "2h"
    defaultDuration: "30m"
```

**Usage via API:**

```bash
# Create a kubectl-debug session
curl -X POST https://breakglass.example.com/api/debugSessions \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"templateRef": "ephemeral-pod-debug", "cluster": "prod-cluster-1", "reason": "Debugging pod connectivity"}'

# Inject ephemeral container into a running pod
curl -X POST https://breakglass.example.com/api/debugSessions/{sessionName}/injectEphemeralContainer \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"namespace": "app-frontend", "podName": "web-abc123", "image": "nicolaka/netshoot:latest"}'

# Create a debug copy of a pod
curl -X POST https://breakglass.example.com/api/debugSessions/{sessionName}/createPodCopy \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"namespace": "app-frontend", "podName": "web-abc123", "debugImage": "busybox:latest"}'
```

### Option 3: Permanent Debug Pods with Breakglass Exec

If you have a permanent "operator-tool" pod, use Breakglass to control exec access:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: debug-tool-access
spec:
  escalatedGroup: "debug-tool-exec"
  description: "Exec into operator-tool pods for debugging"
  allowed:
    clusters: ["prod-cluster-1"]
    groups: ["operations"]
  approvers:
    groups: ["team-leads"]
  maxValidFor: "4h"
```

With Pod Security to limit to specific pods:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: limit-exec-to-debug-pods
spec:
  podSecurityRules:
    # Block exec to all pods except those in debug namespace or with debug label
    exemptions:
      namespaces:
        patterns: ["debug-tools"]
      labels:
        app.kubernetes.io/component: "debug-tool"
    thresholds:
      - maxScore: 0
        action: deny
        reason: "Exec only allowed to debug tool pods. Use debug-tools namespace."
```

### Usage

```bash
# Start a debug session
curl -X POST https://breakglass.example.com/api/debug/sessions/start \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"cluster": "prod-cluster-1", "template": "network-debugging"}'

# Or exec into existing debug pod
kubectl exec -it operator-tool-xyz -- bash
curl http://internal-service:8080/health
openssl s_client -connect external-api.example.com:443
nc -zv database-host 5432
```

---

## TCP Dump and Network Debugging

**Use Case:** Capture network traffic for:
- Debugging connectivity issues
- Analyzing protocol behavior
- Troubleshooting firewall rules

### Configuration Example

For TCP dump, you typically need privileged access to the host network. Use a DebugSession:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: tcpdump-tools
spec:
  podSpec:
    hostNetwork: true  # Required for tcpdump on host interfaces
    containers:
    - name: tcpdump
      image: your-registry/tcpdump:latest
      command: ["/bin/sh", "-c", "sleep infinity"]
      securityContext:
        capabilities:
          add: ["NET_ADMIN", "NET_RAW"]
    nodeSelector:
      # Optionally target specific nodes
      kubernetes.io/hostname: "node-to-debug"
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: network-capture
spec:
  mode: workload
  workloadType: DaemonSet  # Deploy to all/selected nodes
  podTemplateRef: "tcpdump-tools"
  allowed:
    clusters: ["prod-cluster-1"]
    groups: ["network-team", "sre"]
  approvers:
    groups: ["security-team", "sre-leads"]
  constraints:
    maxDuration: "2h"
    defaultDuration: "30m"
```

### Override Pod Security for Network Tools

If SRE needs to access privileged debug pods:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: sre-privileged-debug
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    clusters: ["prod-cluster-1"]
    groups: ["sre"]
  approvers:
    groups: ["sre-leads", "security-team"]
  # Override pod security to allow access to privileged pods
  podSecurityOverrides:
    enabled: true
    maxAllowedScore: 200
    exemptFactors:
      - hostNetwork
      - capabilities
    namespaceScope: ["debug-tools", "kube-system"]
```

### Node-Level Debugging with kubectl-debug Mode

For direct node access using kubectl-debug style operations:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: node-debug-access
spec:
  mode: kubectl-debug
  kubectlDebug:
    nodeDebug:
      enabled: true
      allowedImages: ["nicolaka/netshoot:*", "alpine:*"]
      hostNamespaces:
        hostNetwork: true
        hostPID: true
  allowed:
    clusters: ["prod-cluster-1"]
    groups: ["network-team", "sre"]
  approvers:
    groups: ["sre-leads"]
  constraints:
    maxDuration: "2h"
    defaultDuration: "30m"
```

**Usage via API:**

```bash
# Create a node debug pod
curl -X POST https://breakglass.example.com/api/debugSessions/{sessionName}/createNodeDebugPod \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"nodeName": "node-to-debug"}'

# Then exec into the created pod
kubectl exec -it node-debug-node-to-debug-abc123 -n breakglass-debug -- tcpdump -i any -n port 443
```

---

## M2M Automated Access

**Use Case:** Machine-to-machine automation for:
- Scheduled health check scripts
- Automated kubectl exec commands
- Periodic status queries
- CI/CD pipeline access

### Configuration Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: automation-access
spec:
  escalatedGroup: "automation-exec"
  description: "Automated script access to pods"
  allowed:
    clusters: ["prod-cluster-1", "prod-cluster-2"]
    # Service account identities
    users: ["automation-bot@example.com"]
    groups: ["ci-cd-systems"]
  # Same group can self-approve (automation doesn't wait for humans)
  approvers:
    users: ["automation-bot@example.com"]
  blockSelfApproval: false
  # Longer validity for automation
  maxValidFor: "336h"  # 14 days
  idleTimeout: "168h"   # 7 days
  # Disable email notifications for automation
  disableNotifications: true
```

### Required RBAC (on target cluster)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: automation-exec
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
```

### Limit M2M to Specific Pods

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: limit-automation-scope
spec:
  appliesTo:
    escalationRefs: ["automation-access"]
  podSecurityRules:
    exemptions:
      # Only allow automation to exec into pods with this label
      labels:
        automation-enabled: "true"
    thresholds:
      - maxScore: 0
        action: deny
        reason: "Automation can only exec into pods with automation-enabled=true label"
```

### Automation Script Example

```bash
#!/bin/bash
# Request or refresh automation session
RESPONSE=$(curl -s -X POST https://breakglass.example.com/api/breakglass/request \
  -H "Authorization: Bearer $M2M_TOKEN" \
  -d '{"cluster": "prod-cluster-1", "group": "automation-exec"}')

# Auto-approve (if configured for self-approval)
SESSION_NAME=$(echo $RESPONSE | jq -r '.name')
curl -X POST "https://breakglass.example.com/api/breakglass/approve/$SESSION_NAME" \
  -H "Authorization: Bearer $M2M_TOKEN"

# Now run automated checks
kubectl exec -it my-app-pod -- /scripts/health-check.sh
```

---

## Self-Service Debugging During BIS

**Use Case:** During Business in Service (BIS) transition, teams need frequent debugging access without waiting for approvals every time.

### Configuration Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: bis-debug-access
spec:
  escalatedGroup: "debug-access"
  description: "Self-service debug access during BIS phase"
  allowed:
    clusters: ["prod-cluster-1"]
    groups: ["application-team"]
  # Same group can approve - effectively self-service
  approvers:
    groups: ["application-team"]
  blockSelfApproval: false
  # Longer session for ongoing debugging
  maxValidFor: "8h"
  idleTimeout: "2h"
  # Still require a ticket reference for audit
  requestReason:
    mandatory: true
    description: "BIS ticket or work item reference"
```

### Transition to Production Mode

After BIS is complete, switch to requiring separate approvers:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: prod-debug-access
spec:
  escalatedGroup: "debug-access"
  description: "Production debug access with approval"
  allowed:
    clusters: ["prod-cluster-1"]
    groups: ["application-team"]
  # Different group must approve
  approvers:
    groups: ["sre", "security-team"]
  blockSelfApproval: true
  maxValidFor: "2h"
  requestReason:
    mandatory: true
    description: "Incident ticket and justification"
  approvalReason:
    mandatory: true
    description: "Approval notes"
```

---

## Customer Ingress Pod Restart

**Use Case:** Restart customer-facing ingress pods when certificates get stuck after renewal.

### Configuration Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: ingress-restart
spec:
  escalatedGroup: "ingress-admin"
  description: "Restart ingress controller pods"
  allowed:
    clusters: ["prod-cluster-1", "prod-cluster-2"]
    groups: ["platform-team", "operations"]
  approvers:
    groups: ["platform-leads"]
  maxValidFor: "1h"
  idleTimeout: "30m"
```

### Required RBAC (on target cluster)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ingress-admin
rules:
# For ingress-nginx
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "delete"]
  # Optionally limit to ingress namespace
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets"]
  verbs: ["get", "list", "patch"]
- apiGroups: ["apps"]
  resources: ["deployments/scale"]
  verbs: ["patch"]
---
# Bind only for ingress namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ingress-admin-binding
  namespace: ingress-nginx  # or your ingress namespace
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ingress-admin
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: ingress-admin
```

### Usage

```bash
# Request access
curl -X POST https://breakglass.example.com/api/breakglass/request \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"cluster": "prod-cluster-1", "group": "ingress-admin", "reason": "INC-5678: Certificate stuck after renewal"}'

# After approval, restart ingress
kubectl rollout restart deployment/ingress-nginx-controller -n ingress-nginx

# Or delete specific pods
kubectl delete pod -n ingress-nginx -l app.kubernetes.io/component=controller
```

---

## Best Practices Summary

| Use Case | Escalation Type | Self-Approval | Recommended Duration |
|----------|-----------------|---------------|---------------------|
| Pod Shell Access | Standard | No | 2h |
| Pod Restart | Standard | Yes (dev/staging) | 1h |
| Scaling | Standard | No | 4h |
| Resource Deletion | Standard + DenyPolicy | No | 1h |
| Debug Tool Pods | DebugSession | Yes (dev) | 4h |
| TCP Dump | DebugSession + Override | No | 30m |
| M2M Automation | Standard | Yes | 14 days |
| BIS Debugging | Standard | Yes | 8h |

### Security Recommendations

1. **Least Privilege**: Grant the minimum permissions needed for each use case
2. **DenyPolicies**: Always protect critical resources (secrets, namespaces)
3. **Pod Security**: Use podSecurityRules to control access to privileged pods
4. **Audit Trail**: Require reasons for sensitive operations
5. **Time Limits**: Keep maxValidFor as short as practical
6. **Separate Approvers**: For production, require different person to approve
