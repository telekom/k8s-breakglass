# Upgrade Guide

This guide covers upgrading the breakglass controller between versions, including breaking changes, migration steps, and rollback procedures.

## General Upgrade Process

### Pre-Upgrade Checklist

1. **Read the CHANGELOG** - Review all changes between your current version and target version
2. **Backup CRDs** - Export all breakglass resources before upgrading
3. **Test in Staging** - Always test upgrades in a non-production environment first
4. **Schedule Maintenance Window** - Plan for brief service interruption during upgrade
5. **Notify Users** - Inform users of planned maintenance

### Backup Commands

```bash
# Backup all breakglass resources
kubectl get breakglassescalations -A -o yaml > escalations-backup.yaml
kubectl get breakglasssessions -A -o yaml > sessions-backup.yaml
kubectl get clusterconfigs -A -o yaml > clusterconfigs-backup.yaml
kubectl get identityproviders -o yaml > identityproviders-backup.yaml
kubectl get mailproviders -o yaml > mailproviders-backup.yaml
kubectl get denypolicies -A -o yaml > denypolicies-backup.yaml
kubectl get debugsessiontemplates -A -o yaml > debugsessiontemplates-backup.yaml
kubectl get debugpodtemplates -A -o yaml > debugpodtemplates-backup.yaml

# Backup secrets
kubectl get secrets -l app=breakglass -A -o yaml > breakglass-secrets-backup.yaml
```

### Standard Upgrade Steps

```bash
# 1. Update CRDs first (always safe to apply newer CRDs)
kubectl apply -f config/crd/bases/

# 2. Update the controller deployment
# Using Helm:
helm upgrade breakglass charts/escalation-config \
  --namespace breakglass-system \
  --values your-values.yaml

# Or using kubectl:
kubectl apply -k config/default/

# 3. Verify deployment
kubectl rollout status deployment/breakglass -n breakglass-system

# 4. Check logs for errors
kubectl logs -l app=breakglass -n breakglass-system --tail=100
```

---

## Version-Specific Migration Guides

### Upgrading to v1.0.0 (from v0.x)

#### Breaking Changes

1. **IdentityProvider CRD is now MANDATORY**
   - The legacy `config.yaml` fields `authorizationserver` and `frontend.identityProviderName` have been removed
   - All OIDC/IDP configuration must now use IdentityProvider CRD

2. **Session State Field Changes**
   - `state` field is now the authoritative source for session validity
   - Timestamp fields are preserved but no longer cleared on state transitions

3. **Multi-IDP Support**
   - New `AllowedIdentityProvidersForRequests` field on BreakglassEscalation
   - Sessions now track `identityProviderName` in spec

#### Migration Steps

**Step 1: Create IdentityProvider CRD**

Before upgrading, create an IdentityProvider resource matching your current config:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: primary-idp
spec:
  primary: true  # Mark as primary for backward compatibility
  oidc:
    authority: "https://keycloak.example.com/realms/master"  # From old config.authorizationserver
    clientID: "breakglass-ui"  # From old config
  # If using Keycloak group sync:
  groupSyncProvider: Keycloak
  keycloak:
    baseURL: "https://keycloak.example.com"
    realm: "master"
    clientID: "breakglass-admin"
    clientSecretRef:
      name: keycloak-secret
      namespace: breakglass-system
      key: clientSecret
```

**Step 2: Apply CRDs**

```bash
kubectl apply -f config/crd/bases/
```

**Step 3: Create IdentityProvider**

```bash
kubectl apply -f identityprovider.yaml
```

**Step 4: Upgrade Controller**

```bash
helm upgrade breakglass charts/escalation-config \
  --namespace breakglass-system \
  --values your-values.yaml
```

**Step 5: Verify IdentityProvider Status**

```bash
kubectl get identityproviders
# Should show Ready status
```

**Step 6: Remove Legacy Config**

After verifying everything works, remove the legacy `authorizationserver` fields from your config file or Helm values.

---

### Upgrading to v0.9.0 (from v0.8.x)

#### Breaking Changes

1. **Debug Sessions Feature**
   - New CRDs: `DebugSession`, `DebugSessionTemplate`, `DebugPodTemplate`
   - Requires `--debug-sessions-enabled=true` flag to enable

2. **ClusterConfig Status Subresource**
   - Status updates now require proper status subresource handling
   - Custom controllers interacting with ClusterConfig need updates

#### Migration Steps

**Step 1: Apply New CRDs**

```bash
kubectl apply -f config/crd/bases/breakglass.t-caas.telekom.com_debugsessions.yaml
kubectl apply -f config/crd/bases/breakglass.t-caas.telekom.com_debugsessiontemplates.yaml
kubectl apply -f config/crd/bases/breakglass.t-caas.telekom.com_debugpodtemplates.yaml
```

**Step 2: Upgrade Controller**

```bash
helm upgrade breakglass charts/escalation-config \
  --namespace breakglass-system \
  --set debugSessions.enabled=true
```

---

### Upgrading to v0.8.0 (from v0.7.x)

#### Breaking Changes

1. **DenyPolicy Enhancements**
   - New `namespaceSelector` field for namespace-scoped policies
   - Existing policies without namespace selectors continue to work

2. **Metrics Endpoint Changes**
   - Additional metrics for debug sessions
   - Some metric names may have changed

#### Migration Steps

Standard upgrade - no special migration required.

---

## Rollback Procedures

### Quick Rollback

If the upgrade fails, rollback to the previous version:

```bash
# Using Helm
helm rollback breakglass -n breakglass-system

# Using kubectl (if you have the previous manifests)
kubectl apply -k config/default-previous/
```

### Full Rollback with CRD Reversion

If CRD changes cause issues:

```bash
# 1. Scale down controller
kubectl scale deployment/breakglass -n breakglass-system --replicas=0

# 2. Restore resources from backup
kubectl apply -f escalations-backup.yaml
kubectl apply -f sessions-backup.yaml

# 3. Apply previous CRD versions
kubectl apply -f previous-crds/

# 4. Deploy previous controller version
kubectl apply -k config/default-v0.8/

# 5. Scale up
kubectl scale deployment/breakglass -n breakglass-system --replicas=2
```

### Handling CRD Conversion Webhook Issues

If you encounter CRD conversion issues after upgrade:

```bash
# Check webhook status
kubectl get validatingwebhookconfigurations breakglass-validating-webhook-configuration -o yaml

# Check conversion webhook logs
kubectl logs -l app=breakglass -n breakglass-system | grep -i conversion

# Temporarily disable webhook if needed (CAUTION: reduces validation)
kubectl delete validatingwebhookconfigurations breakglass-validating-webhook-configuration
```

---

## Common Upgrade Issues

### Issue: IdentityProvider Not Ready

**Symptoms:**
- Controller logs show "identity provider not loaded"
- API returns 404 on `/api/identity-provider`

**Resolution:**
```bash
# Check IdentityProvider status
kubectl get identityproviders -o wide
kubectl describe identityprovider primary-idp

# Check if secrets are accessible
kubectl get secret keycloak-secret -n breakglass-system

# Check controller logs
kubectl logs -l app=breakglass -n breakglass-system | grep -i identity
```

### Issue: Sessions Stuck in Pending

**Symptoms:**
- Sessions created but never transition to Approved
- Approvers not receiving notifications

**Resolution:**
```bash
# Check if escalation exists and is valid
kubectl get breakglassescalations -A

# Check if mail provider is configured
kubectl get mailproviders

# Check session status
kubectl describe breakglasssession <session-name>
```

### Issue: Authorization Webhook Errors

**Symptoms:**
- Target cluster users getting denied unexpectedly
- Webhook latency spikes

**Resolution:**
```bash
# Check webhook logs
kubectl logs -l app=breakglass -n breakglass-system | grep -i webhook

# Verify ClusterConfig connectivity
kubectl get clusterconfigs -o wide

# Check target cluster accessibility
kubectl --kubeconfig=/path/to/target/kubeconfig get pods -n kube-system
```

### Issue: CRD Validation Errors

**Symptoms:**
- `kubectl apply` fails with validation errors
- Resources created before upgrade fail validation

**Resolution:**
```bash
# Check what fields are invalid
kubectl apply -f resource.yaml --dry-run=server

# If necessary, edit resources to match new schema
kubectl edit breakglassescalation <name>
```

---

## Zero-Downtime Upgrade (Advanced)

For production environments requiring zero-downtime upgrades:

### Prerequisites

- Multiple replicas running (`replicas >= 2`)
- Leader election enabled
- PodDisruptionBudget configured

### Procedure

```bash
# 1. Apply CRD updates (non-disruptive)
kubectl apply -f config/crd/bases/

# 2. Perform rolling update
kubectl set image deployment/breakglass \
  breakglass=ghcr.io/telekom/k8s-breakglass:v1.0.0 \
  -n breakglass-system

# 3. Monitor rollout
kubectl rollout status deployment/breakglass -n breakglass-system

# 4. Verify health
kubectl get pods -l app=breakglass -n breakglass-system -o wide
```

### Canary Deployment (Optional)

For extra safety, deploy a canary replica first:

```bash
# 1. Create canary deployment
kubectl apply -f canary-deployment.yaml

# 2. Route small % of traffic to canary
# (Configure based on your ingress controller)

# 3. Monitor canary metrics and logs

# 4. If successful, proceed with full rollout
```

---

## Post-Upgrade Verification

After any upgrade, verify:

```bash
# 1. Controller is healthy
kubectl get pods -l app=breakglass -n breakglass-system

# 2. All CRDs are installed
kubectl get crd | grep breakglass

# 3. IdentityProvider is Ready
kubectl get identityproviders -o wide

# 4. ClusterConfigs are Ready
kubectl get clusterconfigs -o wide

# 5. Test authentication
# (Attempt login via frontend)

# 6. Test session creation
# (Create and approve a test session)

# 7. Test authorization webhook
# (Verify approved session grants access)

# 8. Check metrics are flowing
kubectl port-forward svc/breakglass 8443:8443 -n breakglass-system
curl -k https://localhost:8443/metrics
```

---

## Related Documentation

- [CHANGELOG](../CHANGELOG.md) - Complete version history
- [Installation Guide](./installation.md) - Fresh installation instructions
- [Configuration Reference](./configuration-reference.md) - All configuration options
- [Production Deployment Checklist](./production-deployment-checklist.md) - Production readiness
- [Troubleshooting](./troubleshooting.md) - Common issues and solutions
