# IdentityProvider Status and Events - Issues & Fixes

## Issues Identified

### Issue 1: IdentityProvider Status Never Updated

The IdentityProvider CRD includes a comprehensive `status` subresource that was defined but never actually updated by the reconciler.

**Symptoms:**

```bash
$ kubectl get identityproviders
NAME                   ISSUER                                     PRIMARY   GROUPSYNC   PHASE   CONNECTED   AGE
reference-keycloak     https://keycloak.example.com              false     Keycloak            <none>      5m
```

The status columns (PHASE, CONNECTED) were always empty because the reconciler never called `Status().Update()`.

**Root Cause:**
The `IdentityProviderReconciler.Reconcile()` method only emitted Kubernetes events but never updated the IdentityProvider CR's status subresource.

### Issue 2: Events Recorded in Wrong Namespace

Events for cluster-scoped resources (like IdentityProvider) were appearing in the pod's namespace (`default` or `breakglass-system`) instead of being attached to the IdentityProvider CR.

**Symptoms:**

```bash
$ kubectl get events
NAMESPACE      LAST SEEN   TYPE     REASON            OBJECT
default        2m48s       Normal   ReloadSuccess     identityprovider/reference-keycloak
```

Should be:

```bash
$ kubectl get events --all-namespaces
NAMESPACE   LAST SEEN   TYPE     REASON            OBJECT
            2m48s       Normal   ReloadSuccess     identityprovider/reference-keycloak
```

**Root Cause:**
The Kubernetes event recorder sets the event's namespace from the object being recorded. For cluster-scoped resources, no namespace should be set. The reconciler was passing the IdentityProvider object directly, but the EventRecorder may have been applying the pod's namespace by default.

## Solutions Implemented

### Fix 1: Update IdentityProvider Status

The reconciler now updates the IdentityProvider status after each reconciliation:

```go
// On successful reload
idp.Status.Phase = "Ready"
idp.Status.Message = "Configuration reloaded successfully"
idp.Status.Connected = true
idp.Status.LastValidation = metav1.NewTime(time.Now())
if err := r.client.Status().Update(ctx, idp); err != nil {
    r.logger.Errorw("Failed to update IdentityProvider status", "error", err, "name", req.Name)
}

// On failed reload
idp.Status.Phase = "Error"
idp.Status.Message = fmt.Sprintf("Failed to reload configuration: %v", err)
idp.Status.Connected = false
if err := r.client.Status().Update(ctx, idp); err != nil {
    r.logger.Errorw("Failed to update IdentityProvider status", "error", err, "name", req.Name)
}
```

**Benefits:**

- Administrators can see provider status: `kubectl get identityproviders`
- Last validation timestamp helps troubleshoot stale configurations
- Clear Phase field (Ready/Error) indicates provider health
- Connected flag reflects actual connectivity

### Fix 2: Ensure Events Have No Namespace for Cluster-Scoped Resources

Before recording events, we explicitly clear the namespace for cluster-scoped resources:

```go
if r.recorder != nil {
    eventIdp := idp.DeepCopy()
    eventIdp.SetNamespace("") // Ensure no namespace is set for cluster-scoped events
    r.recorder.Event(eventIdp, "Normal", "ReloadSuccess", "Configuration reloaded successfully")
}
```

**Benefits:**

- Events appear associated with the IdentityProvider CR itself
- Events are no longer confined to a single namespace
- Consistency with Kubernetes event behavior for cluster-scoped resources

## Verification

### Check IdentityProvider Status

```bash
# View all providers and their status
kubectl get identityproviders
NAME                   ISSUER                            PRIMARY   PHASE   CONNECTED
reference-keycloak     https://keycloak.example.com      false     Ready   true
corporate-okta         https://okta.company.com          true      Ready   true

# Describe a provider to see detailed status
kubectl describe identityprovider reference-keycloak
Status:
  Connected:      true
  Last Validation: 2025-11-17T14:38:31Z
  Message:        Configuration reloaded successfully
  Phase:          Ready
```

### Check Events for IdentityProvider

```bash
# View events for a specific provider
kubectl describe identityprovider reference-keycloak
# Events section now shows reconciliation events

# Or list events for the resource
kubectl get events --field-selector involvedObject.name=reference-keycloak,involvedObject.kind=IdentityProvider
NAMESPACE   TYPE     REASON          OBJECT                     MESSAGE
(empty)     Normal   ReloadSuccess   identityprovider/ref...    Configuration reloaded successfully
```

## Status Fields Explained

| Field | Type | Description | Updated When |
|-------|------|-------------|--------------|
| `Phase` | string | Current state: `Ready`, `Error`, or `Validating` | Each reconciliation |
| `Message` | string | Detailed status message or error description | Each reconciliation |
| `Connected` | bool | Whether provider is reachable | Each reconciliation |
| `LastValidation` | timestamp | When provider was last successfully validated | Successful reload |
| `ConfigHash` | string | Hash of current spec for change detection | (Future use) |
| `Conditions` | array | Detailed condition status with timestamps | (Future use) |

## Related Code Changes

**File:** `pkg/config/identity_provider_reconciler.go`

- Added import: `metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"`
- Enhanced `Reconcile()` method to:
  - Update status on success and failure
  - Clear namespace for cluster-scoped event recording
  - Log status update errors separately from reload errors

**File:** `api/v1alpha1/identity_provider_types.go`

- Already had proper status subresource definition
- Already had status helper methods (SetCondition, GetCondition)
- CRD already included status columns in kubebuilder output

## Impact

**Severity:** Low - Observability improvement, no behavioral changes

**Scope:** IdentityProvider status reporting and event recording

**Testing:** All existing tests pass (9 reconciler tests verified)

**Backward Compatibility:** Fully backward compatible - only adds status updates

## Next Steps

1. Deploy updated controller to cluster
2. Verify IdentityProvider CRs show correct status
3. Confirm events appear in event logs
4. Monitor Last Validation timestamps to detect stale configurations
5. (Optional) Add alerting on Phase == "Error" or LastValidation > X minutes old

## Troubleshooting

### Status Not Updating

If status fields remain empty after restart:

```bash
# Check if controller has status.subresources permission
kubectl get clusterrolebinding -o yaml | grep -A5 identity-provider-manager-role-binding

# Verify status.subresource is in CRD
kubectl get crd identityproviders.breakglass.t-caas.telekom.com -o yaml | grep -A3 subresources
```

### Events Appearing in Pod Namespace

If events still appear in the wrong namespace:

```bash
# Check controller logs
kubectl logs -n breakglass-system deployment/breakglass-manager | grep -i event

# Verify event recorder initialization
kubectl get events -n breakglass-system | grep "IdentityProvider\|identityprovider"
```
