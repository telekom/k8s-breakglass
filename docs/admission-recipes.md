<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Typed admission recipes

`DebugSessionTemplate.spec.admissionRecipe` lets an approved DebugSession make
one of two fixed admission changes on the target cluster for the session
lifetime, and reverts it automatically:

| Action | Change | Revert |
| --- | --- | --- |
| `policy-audit` | Kyverno `ValidatingPolicy` (`policies.kyverno.io`): `spec.validationActions` that contains `Deny` becomes `[Audit]` | the recorded original list |
| `webhook-fail-open` | one webhook of a `ValidatingWebhookConfiguration` or `MutatingWebhookConfiguration`: `failurePolicy` `Fail` (or unset) becomes `Ignore` | `Fail` |

The controller performs the change through its existing privileged
ClusterConfig identity. The requester never gets RBAC on the target objects,
never supplies a field, value or patch, and only chooses targets from the
template allowlist. Design background: [proposal](proposals/typed-admission-recipes.md).

## Template

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: emergency-policy-audit
spec:
  displayName: Emergency policy audit switch
  allowed:
    groups: [YOUR_PLATFORM_REQUESTERS]
  approvers:
    groups: [YOUR_INDEPENDENT_APPROVERS]
  constraints:
    maxDuration: 30m        # required, at most 2h; no idleTimeout, no renewal
    defaultDuration: 30m
  requestReason:
    mandatory: true
  admissionRecipe:
    action: policy-audit
    flux: true              # also set the per-object Flux annotations (see below)
    allowedTargets:
      - {kind: ValidatingPolicy, apiVersion: policies.kyverno.io/v1, name: require-pod-probes}
      - {kind: ValidatingPolicy, apiVersion: policies.kyverno.io/v1, name: require-labels}
    deniedTargetLabels:     # checked on the live object before every write
      - key: categories
        valuePattern: '(.+_)?(platform-)?critical(_.+)?'
```

For `webhook-fail-open`, each allowlist entry names the configuration and one
webhook:

```yaml
  admissionRecipe:
    action: webhook-fail-open
    allowedTargets:
      - kind: ValidatingWebhookConfiguration
        name: ingress-nginx-admission
        webhook: validate.nginx.ingress.kubernetes.io
```

Validation rejects a template that also has a Pod template, workload type,
kubectl-debug, auxiliary resources, scheduling, impersonation, terminal
sharing or artifact settings, a missing or longer than 2h `maxDuration`, an
`idleTimeout`, renewal, auto-approval, `blockSelfApproval: false`, duplicate or
malformed allowlist entries, or an invalid `valuePattern`. `admissionRecipe`
and `nodeMaintenance` are mutually exclusive.

`deniedTargetLabels[].valuePattern` is an RE2 expression matched against the
**whole** label value. A target whose live label matches is refused even if it
is allowlisted, so a policy that gains a protected category later cannot be
switched.

## Request

```json
{
  "templateRef": "emergency-policy-audit",
  "cluster": "prod-cluster-01",
  "requestedDuration": "20m",
  "reason": "INC123: require-pod-probes blocks the hotfix rollout",
  "admissionRecipe": {"targets": [
    {"kind": "ValidatingPolicy", "apiVersion": "policies.kyverno.io/v1", "name": "require-pod-probes"}
  ]}
}
```

Each target must equal one allowlist entry exactly (1 to 16 targets, no
duplicates). `apiVersion` is required for a `ValidatingPolicy` and must be
empty for a webhook configuration.
Generic inputs (`nodeSelector`, `extraDeployValues`, scheduling options,
invited participants) are rejected. At request time the controller reads the
live targets and rejects the request if a target is missing, denied by label,
already changed by another session, or not at its starting value
(`Deny` / `Fail`).

## Lifecycle

1. **Approval.** Always independent: the requester cannot approve, in every
   stage, and auto-approval is not possible.
2. **Apply** when the session becomes Active. The controller adds the
   `breakglass.t-caas.telekom.com/admission-recipe-revert` finalizer, emits a
   synchronous audit event (`debug_session.admission_recipe.applied`; it is the
   intent receipt and precedes every write, so its targets are still
   `not-applied`; the values written are in the session status and in the
   `.reverted` event), and for
   each target: re-reads it, re-checks the denied labels, owner and starting
   value, records the original value in `status.admissionRecipe` **before**
   writing, re-validates the live session approval, and updates the object
   with its read `resourceVersion`. It also sets the annotations
   `breakglass.t-caas.telekom.com/admission-recipe-session` (session UID) and
   `breakglass.t-caas.telekom.com/admission-recipe-expires-at`. The owner
   annotation is on the policy or webhook configuration, so a second session
   for another webhook of the same configuration is refused while the first
   one holds it.
3. **Watch.** Every 30 seconds the controller re-reads each target. If the
   field or the session annotation changed, a synchronous
   `debug_session.admission_recipe.drift` audit event is emitted, then the
   target becomes `drifted` and
   `breakglass_admission_recipe_operations_total{operation="drift"}`
   increases. If the audit sink is down, the target stays `applied` and the
   next check reports the drift again. The controller never overwrites drift.
4. **Revert** on terminate, reject, failure, expiry (hard `maxDuration`) and
   on deletion of the DebugSession (the finalizer keeps it until the revert
   is done). A target is restored when it still holds the value this session
   wrote and carries this session's annotation, or no owner annotation at all
   (someone stripped only the annotation): restoring the original never widens
   admission. A target whose value someone else changed keeps its current
   value and only loses the annotations (`revert-skipped`), and a target owned
   by another session is left alone; alert on
   `breakglass_admission_recipe_operations_total{operation="revert",result="skipped"}`.
   A synchronous
   `debug_session.admission_recipe.reverted` event follows the last target.
   A target whose webhook entry disappeared is `revert-skipped` with the
   reason, and its annotations are still removed. Revert failures are
   retried and stay visible in the session's `CleanupFailed` condition.
   If the ClusterConfig is deleted before the revert, the finalizer keeps
   the session: restore the target by hand, remove its
   `admission-recipe-*` annotations, then remove the finalizer
   `breakglass.t-caas.telekom.com/admission-recipe-revert` on the hub. A
   deleted session that is still active, for example one that expired while
   the controller was down, is first marked terminal and then reverted.
5. **Restart safety.** The original value and intent are persisted before
   each write, so a controller restart either finds the write done (the
   session annotation is present) or not done, and reverts accordingly.

The session has no workload and allows no exec, attach, logs or
port-forward.

## GitOps controllers

With `flux: true` the recipe also sets, for the window,
`helm.toolkit.fluxcd.io/driftDetection: disabled` (helm-controller drift
correction) and `kustomize.toolkit.fluxcd.io/reconcile: disabled`
(kustomize-controller apply and prune) on each target, and restores the
previous values on revert. Without it, a GitOps controller can revert the
change within its interval; the recipe then reports drift. Policy engines that
own their webhook configurations re-assert `failurePolicy` when they are
healthy again, which is also reported as drift.

## Spoke permissions

The controller's ClusterConfig identity needs `get` and `update` on the
allowlisted kinds (`validatingpolicies.policies.kyverno.io`,
`validatingwebhookconfigurations` / `mutatingwebhookconfigurations`), which
can be scoped with `resourceNames`. Breakglass ships no spoke role for this;
grant it to the ClusterConfig identity, for example:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-admission-recipes
rules:
  - apiGroups: ["policies.kyverno.io"]
    resources: ["validatingpolicies"]
    resourceNames: ["require-labels"]        # the allowlisted policies
    verbs: ["get", "update"]
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["validatingwebhookconfigurations"]
    resourceNames: ["example-webhook"]       # the allowlisted configurations
    verbs: ["get", "update"]
```

## Metrics and audit

- `breakglass_admission_recipe_operations_total{cluster,action,operation,result}`
  with `operation` `apply`, `revert` or `drift`.
- Audit events `debug_session.admission_recipe.applied`, `.drift` and
  `.reverted` are sensitive and delivered synchronously; they carry the
  requester, approver, action and every target with its original and applied
  value. Alert on them in the security monitoring.

## Kind proof

`hack/admission-recipe-kind.sh` runs `TestAdmissionRecipeKind` on a disposable
Kind cluster: a webhook with a Service without endpoints blocks ConfigMap
creates until the approved recipe sets `Ignore`, a terminate after a
controller restart restores `Fail`; a critical-labelled policy is refused and
an allowlisted policy is switched to `Audit` and reverted at expiry.
