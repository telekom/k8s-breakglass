# ValidatingAdmissionPolicy Migration

This document describes the migration of breakglass validation from webhook-based admission to Kubernetes [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) (VAP), which is GA in Kubernetes 1.30+.

## Overview

Breakglass currently validates all CRD admission requests through a validating webhook. ValidatingAdmissionPolicy offers several advantages:

| Feature | Webhook | VAP |
|---------|---------|-----|
| Latency | Network round-trip to webhook pod | In-process (API server) |
| Availability | Depends on webhook pod health | Built-in, no external dependency |
| Audit logging | Manual | Automatic (built-in audit events) |
| Language | Go code | CEL expressions |
| Cross-resource checks | Supported | Limited (paramKind only) |

The migration is **incremental** — VAP runs alongside webhooks, providing defense-in-depth. Complex validations that require cross-resource lookups (e.g., checking referenced IdentityProviders exist) remain in the webhook.

## Migration Phases

| Phase | Action | Mode | K8s Version |
|-------|--------|------|-------------|
| **1 (current)** | Deploy VAP alongside webhooks | **Warn + Audit** | 1.30+ |
| 2 | Move simple validations to Deny mode | Deny + Audit | 1.30+ |
| 3 | Add parameterized policies (paramKind) | Deny + Audit | 1.30+ |
| 4 | Remove webhook for VAP-covered validations | N/A | 1.32+ |

## Phase 1: Warn Mode (Current)

Phase 1 deploys VAP resources in **Warn** mode. Validation failures produce:

- **Warnings** in API responses (visible to `kubectl` users)
- **Audit log entries** for monitoring and alerting

By default, Phase 1 uses `Warn` + `Audit`, so VAP does not block requests and the
existing webhook remains the enforcement point. If `validationActions` includes
`Deny`, VAP becomes enforcing and can block failing requests.

### Covered Validations

#### BreakglassSession

| Validation | CEL Expression |
|------------|---------------|
| `spec.cluster` required on create | `oldObject != null \|\| (has(object.spec.cluster) && object.spec.cluster.size() > 0)` |
| `spec.user` required on create | `oldObject != null \|\| (has(object.spec.user) && object.spec.user.size() > 0)` |
| `spec.grantedGroup` required on create | `oldObject != null \|\| (has(object.spec.grantedGroup) && object.spec.grantedGroup.size() > 0)` |
| Spec immutability on update | `oldObject == null \|\| object.spec == oldObject.spec` |
| Valid state transitions | `oldObject == null \|\| !has(oldObject.status) \|\| !has(oldObject.status.state) \|\| oldObject.status.state == "" \|\| oldObject.status.state == object.status.state \|\| (oldObject.status.state == "Pending" && object.status.state in ["Approved", "WaitingForScheduledTime", "Rejected", "Withdrawn", "ApprovalTimeout"]) \|\| (oldObject.status.state == "WaitingForScheduledTime" && object.status.state in ["Approved", "Withdrawn", "Expired"]) \|\| (oldObject.status.state == "Approved" && object.status.state in ["Expired", "IdleExpired"])` |

Session state validation matches both the main resource and its `/status` subresource, so controller status updates are covered while the guarded spec checks continue to require an unchanged spec.

#### BreakglassEscalation

| Validation | CEL Expression |
|------------|---------------|
| Approvers non-empty | `has(object.spec.approvers) && ((has(object.spec.approvers.groups) && object.spec.approvers.groups.size() > 0) \|\| (has(object.spec.approvers.users) && object.spec.approvers.users.size() > 0))` |
| `escalatedGroup` identifier format | `has(object.spec.escalatedGroup) && object.spec.escalatedGroup.size() > 0 && object.spec.escalatedGroup.matches('^[a-zA-Z0-9._:-]+$')` |
| No empty `allowed.groups` entries | `!has(object.spec.allowed) \|\| !has(object.spec.allowed.groups) \|\| object.spec.allowed.groups.all(g, g.size() > 0)` |
| No empty `allowed.clusters` entries | `!has(object.spec.allowed) \|\| !has(object.spec.allowed.clusters) \|\| object.spec.allowed.clusters.all(c, c.size() > 0)` |
| No duplicate `allowed.groups` | `!has(object.spec.allowed) \|\| !has(object.spec.allowed.groups) \|\| object.spec.allowed.groups.all(g, object.spec.allowed.groups.exists_one(x, x == g))` |
| No duplicate `allowed.clusters` | `!has(object.spec.allowed) \|\| !has(object.spec.allowed.clusters) \|\| object.spec.allowed.clusters.all(c, object.spec.allowed.clusters.exists_one(x, x == c))` |
| IDP legacy mutual exclusion | `!has(object.spec.allowedIdentityProviders) \|\| object.spec.allowedIdentityProviders.size() == 0 \|\| (!has(object.spec.allowedIdentityProvidersForRequests) \|\| object.spec.allowedIdentityProvidersForRequests.size() == 0) && (!has(object.spec.allowedIdentityProvidersForApprovers) \|\| object.spec.allowedIdentityProvidersForApprovers.size() == 0)` |
| IDP split-field symmetry | `(!has(object.spec.allowedIdentityProvidersForRequests) \|\| object.spec.allowedIdentityProvidersForRequests.size() == 0) == (!has(object.spec.allowedIdentityProvidersForApprovers) \|\| object.spec.allowedIdentityProvidersForApprovers.size() == 0)` |

#### ClusterConfig

| Validation | CEL Expression |
|------------|---------------|
| Auth config mutual exclusivity | `(has(object.spec.kubeconfigSecretRef) && object.spec.kubeconfigSecretRef.name.size() > 0) != ((has(object.spec.oidcAuth) && has(object.spec.oidcAuth.issuerURL) && object.spec.oidcAuth.issuerURL.size() > 0) \|\| (has(object.spec.oidcFromIdentityProvider) && has(object.spec.oidcFromIdentityProvider.name) && object.spec.oidcFromIdentityProvider.name.size() > 0))` |
| `kubeconfigSecretRef.name` required | `!has(object.spec.kubeconfigSecretRef) \|\| object.spec.kubeconfigSecretRef.name.size() > 0` |
| No duplicate `identityProviderRefs` | `!has(object.spec.identityProviderRefs) \|\| object.spec.identityProviderRefs.all(ref, object.spec.identityProviderRefs.exists_one(x, x == ref))` |

#### IdentityProvider

| Validation | CEL Expression |
|------------|---------------|
| OIDC authority required + HTTPS | `has(object.spec.oidc) && has(object.spec.oidc.authority) && object.spec.oidc.authority.startsWith('https://')` |
| OIDC clientID required | `has(object.spec.oidc) && has(object.spec.oidc.clientID) && object.spec.oidc.clientID.size() > 0` |
| JWKS endpoint HTTPS | `!has(object.spec.oidc) \|\| !has(object.spec.oidc.jwksEndpoint) \|\| object.spec.oidc.jwksEndpoint.size() == 0 \|\| object.spec.oidc.jwksEndpoint.startsWith('https://')` |
| OIDC insecure TLS forbidden | `!has(object.spec.oidc) \|\| !has(object.spec.oidc.insecureSkipVerify) \|\| object.spec.oidc.insecureSkipVerify == false` |
| Issuer HTTPS | `!has(object.spec.issuer) \|\| object.spec.issuer.size() == 0 \|\| object.spec.issuer.startsWith('https://')` |
| Keycloak config conditional | `!has(object.spec.groupSyncProvider) \|\| object.spec.groupSyncProvider != 'Keycloak' \|\| (has(object.spec.keycloak) && has(object.spec.keycloak.baseURL) && object.spec.keycloak.baseURL.size() > 0 && has(object.spec.keycloak.realm) && object.spec.keycloak.realm.size() > 0 && has(object.spec.keycloak.clientID) && object.spec.keycloak.clientID.size() > 0)` |
| Keycloak insecure TLS forbidden | `!has(object.spec.keycloak) \|\| !has(object.spec.keycloak.insecureSkipVerify) \|\| object.spec.keycloak.insecureSkipVerify == false` |
| Keycloak config forbidden | `!has(object.spec.keycloak) \|\| !has(object.spec.groupSyncProvider) \|\| object.spec.groupSyncProvider == 'Keycloak'` |

### Validations Remaining in Webhook

These validations **cannot** be expressed in CEL without cross-resource lookups:

- **`ensureClusterWideUniqueName`** — Requires listing other resources of the same kind
- **`ensureClusterWideUniqueIssuer`** — Requires listing IdentityProvider resources
- **`validateIdentityProviderRefs`** — Requires looking up referenced IdentityProviders
- **`validateMailProviderReference`** — Requires looking up referenced MailProviders
- **`validateSessionIdentityProviderAuthorization`** — Requires cross-referencing escalations and IDPs
- **BreakglassSession request reason policy** — Depends on the matched escalation's stored reason policy
- **Go template syntax validation** — Cannot validate Go templates via CEL
- **Template dry-run rendering** — Requires full Go runtime

## Enabling VAP

### Prerequisites

- Kubernetes 1.30+ (ValidatingAdmissionPolicy GA)
- The `admissionregistration.k8s.io/v1` API group available

### Deploy

Add the VAP kustomize component to your overlay:

```yaml
# In your kustomization.yaml
components:
  - ../../components/vap
```

Build and apply:

```bash
kustomize build config/test-overlays/vap/ | kubectl apply -f -
```

### Helm deployments

The `escalation-config` chart can also render these VAP objects through
`validatingAdmissionPolicy.enabled=true`. The policy and binding names are
static cluster-scoped names. Enable them from only one release per cluster.

If a cluster already installed the VAP objects through this kustomize component,
leave the chart value disabled. To move ownership to Helm, first remove or adopt
the existing `ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding`
objects so Helm does not collide with unmanaged cluster-scoped resources.

The Helm value `validatingAdmissionPolicy.validationActions` accepts `Deny`,
`Warn`, and `Audit`. `Deny` is enforcing and blocks requests that fail a policy,
so keep the default `Warn, Audit` actions during phase 1 unless request blocking
is intentional. `Deny` and `Warn` cannot be combined.

### Verify

Check policies are deployed:

```bash
kubectl get validatingadmissionpolicies -l breakglass.t-caas.telekom.com/phase=1
```

Expected output:

```
NAME                                       VALIDATIONS   PARAMKIND   MATCHCONDITIONS
breakglass-clusterconfig-validation        3             <unset>     0
breakglass-escalation-validation           8             <unset>     0
breakglass-identityprovider-validation     8             <unset>     0
breakglass-session-validation              5             <unset>     0
```

Check bindings:

```bash
kubectl get validatingadmissionpolicybindings -l breakglass.t-caas.telekom.com/phase=1
```

### Monitor Warnings

Watch for VAP warnings in API server audit logs:

```bash
# Check audit logs for VAP warnings
kubectl logs -n kube-system kube-apiserver-<node> | grep "ValidatingAdmissionPolicy"
```

Or query warnings from kubectl output when creating/updating resources:

```bash
kubectl apply -f my-escalation.yaml
# Warning: breakglass-escalation-validation: spec.allowed.groups must not contain empty entries
```

## Switching to Deny Mode (Phase 2)

After monitoring Warn mode and confirming no false positives, switch to Deny mode by patching the bindings in your overlay:

```yaml
patches:
  - target:
      kind: ValidatingAdmissionPolicyBinding
      labelSelector: "breakglass.t-caas.telekom.com/phase=1"
    patch: |
      - op: replace
        path: /spec/validationActions
        value:
          - Deny
          - Audit
```

**Important:** Only switch after:

1. Monitoring Warn-mode audit logs for at least 2 weeks
2. Confirming zero false positives
3. Verifying all existing resources pass VAP validation

## Troubleshooting

### Policy Not Taking Effect

1. Verify K8s version supports VAP:

   ```bash
   kubectl api-versions | grep admissionregistration.k8s.io/v1
   ```

2. Check policy status:

   ```bash
   kubectl get validatingadmissionpolicies breakglass-session-validation -o yaml
   ```

3. Verify binding exists:

   ```bash
   kubectl get validatingadmissionpolicybindings -l breakglass.t-caas.telekom.com/phase=1
   ```

### False Positives in Warn Mode

If you see unexpected warnings:

1. Check which policy triggered the warning (the warning message includes the policy name)
2. Inspect the resource that triggered it
3. If the warning is incorrect, file a bug — the webhook remains the source of truth in Phase 1

### Webhook vs VAP Conflict

In Phase 1, both webhook and VAP validate simultaneously. If they disagree:

- **Webhook blocks, VAP warns** — Webhook decision wins (request blocked)
- **Webhook allows, VAP warns** — Request succeeds with warning
- **Both agree** — Expected behavior

## Related Documentation

- [Ingress Configuration](ingress-configuration.md) — Network setup
- [Installation Guide](installation.md) — Step-by-step deployment
- [Kubernetes VAP Documentation](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) — Upstream reference
