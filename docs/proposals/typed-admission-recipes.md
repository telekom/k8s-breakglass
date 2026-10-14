<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Proposal: typed admission recipes (policy audit switch, webhook fail-open)

Status: proposal. Target: a later 0.3.0 release candidate.

## Problem

Two admission emergencies recur in production:

1. **A policy blocks a rollout.** A validating policy (for example a Kyverno
   `ValidatingPolicy` with `validationActions: [Deny]`) rejects a platform
   rollout that must proceed now. Today an operator needs cluster-admin, edits
   the policy by hand, and must remember to revert it. A GitOps controller may
   revert the edit at a random time, or never.
2. **An admission webhook is down.** A webhook with `failurePolicy: Fail`
   whose backend is unavailable blocks every matching request (for example
   all Pod creates when the policy engine is down). Today an operator needs
   cluster-admin to set `failurePolicy: Ignore` or delete the configuration,
   with no expiry and no record of what was changed.

Both are the same shape: a reviewed field transition on one named object for
a bounded time, with a guaranteed revert. A generic escalation (cluster-admin)
gives far more than that and reverts nothing. An auxiliary resource cannot do
it either: auxiliary resources are created and deleted, not patched and
reverted, and deleting the target object at session end would be wrong.

## Goals

- A **typed recipe** on `DebugSessionTemplate`, executed by the controller
  through its existing spoke identity, never by the requester.
- Requesters choose only **targets from an administrator allowlist**; the
  action and the field transition are fixed by the template.
- **Independent approval** through the existing DebugSession approval; no
  self-approval, no auto-approval (same rules as `nodeMaintenance`).
- **Automatic revert** when the session reaches a terminal state, at
  `status.expiresAt`, and after a controller restart (level-triggered).
- **Drift detection**: if the object changes during the window, report it
  (condition, Kubernetes Event, metric, audit event) and do not fight.
- **Durable audit** events for apply, revert, drift and refusal.
- **Denied targets** that a deployment can declare by label, checked live on
  the spoke at apply time (for example policies that guard protected
  namespaces).

## Non-goals

- Arbitrary patches, JSON patch input or free-form field paths.
- Deleting webhook configurations or policies.
- Changing a policy's rules, match constraints or exceptions.
- Persisting a change beyond the session; persistent changes go through GitOps.

## API sketch

```yaml
# DebugSessionTemplate (administrator)
spec:
  mode: workload            # no pod template, no workload: like nodeMaintenance
  constraints:
    maxDuration: 30m        # hard cap for the revert deadline
  admissionRecipe:
    action: policy-audit    # or: webhook-fail-open
    allowedTargets:
      # policy-audit: one policy object per entry
      - apiVersion: policies.kyverno.io/v1   # the version served by the installed Kyverno
        kind: ValidatingPolicy
        name: require-pod-probes
      # webhook-fail-open: one webhook of one configuration per entry
      - kind: ValidatingWebhookConfiguration
        name: ingress-nginx-admission
        webhook: validate.nginx.ingress.kubernetes.io
    deniedTargetSelector:   # refused at apply time even if allowlisted
      matchExpressions:
        - {key: categories, operator: In, values: [platform-critical]}
    gitOps:
      flux: true            # see "GitOps controllers"
```

```json
// POST /debugSessions (requester)
{
  "templateRef": "emergency-policy-audit",
  "cluster": "prod-cluster-01",
  "requestedDuration": "20m",
  "reason": "INC123: require-pod-probes blocks the hotfix rollout",
  "admissionRecipe": {"targets": [{"kind": "ValidatingPolicy", "name": "require-pod-probes"}]}
}
```

Validation: every requested target must equal an allowlist entry; duplicates,
unknown fields and empty lists are rejected. The action is never a request
field.

### Actions

| Action | Field transition | Revert |
| --- | --- | --- |
| `policy-audit` | Kyverno `ValidatingPolicy`/`ImageValidatingPolicy`: `spec.validationActions` from a set containing `Deny` to `[Audit]`. Legacy `ClusterPolicy`: `spec.validationFailureAction` `Enforce` → `Audit` (and per-rule overrides). | Restore the recorded original value. |
| `webhook-fail-open` | `webhooks[name=<webhook>].failurePolicy` `Fail` (or unset, which means `Fail`) → `Ignore` on the named Validating/MutatingWebhookConfiguration. | Restore the original value (`Fail` or unset). |

The recipe refuses a target whose current value is not the expected starting
value (already `Audit`/`Ignore`): there is nothing to revert, and two
sessions must not own the same field.

## Lifecycle

1. **Approve.** Normal DebugSession approval. The binding approvers are
   captured immutably, as for `nodeMaintenance`.
2. **Apply** (session becomes Active). For each target, in one reconcile:
   - re-read the target on the spoke; refuse if it matches
     `deniedTargetSelector` or does not have the expected starting value;
   - patch with an optimistic `resourceVersion` precondition: set the field,
     set annotations `breakglass.t-caas.telekom.com/recipe-session` (session
     UID) and `breakglass.t-caas.telekom.com/recipe-original` (JSON of the
     original value), and, if enabled, the GitOps annotation;
   - record `{target, original, applied, resourceVersion}` in
     `status.admissionRecipe` on the hub before reporting success.
3. **Watch.** Every reconcile (and at least every minute) re-reads each
   target. If the field no longer equals the applied value, or the session
   annotation is gone: set condition `RecipeDrift=True`, emit an Event and an
   audit event, increment `breakglass_admission_recipe_drift_total{action}`.
   Do not re-apply.
4. **Revert** at the first of: terminal state, `status.expiresAt`, template
   `maxDuration`. For each target: if the field still equals the applied
   value and the session annotation matches, restore the original and remove
   the annotations; otherwise leave it (drift already reported) and record
   `RevertSkipped` with the reason. Revert failures are retried with backoff
   and stay visible in status and metrics
   (`breakglass_admission_recipe_revert_pending`).
5. **Restart safety.** On start and periodically, the controller lists
   objects carrying `recipe-session` on every spoke and reverts every target
   whose session is terminal, missing or past `expiresAt`. The spoke
   annotation, not controller memory, is the source of truth, so a crash
   between apply and status write still reverts.

Apply happens only after approval, so a rejected or withdrawn request never
changes a target. A hub DebugSession that is deleted directly has no
finalizer; the restart sweep finds its targets by the spoke annotation and
reverts them.

## GitOps controllers

A GitOps controller reverts a manual change at its next reconcile:

- Flux helm-controller with drift detection: with `gitOps.flux: true` the
  recipe also sets
  `helm.toolkit.fluxcd.io/driftDetection: disabled` on the target and removes
  it on revert.
- Flux kustomize-controller re-applies with server-side apply every
  interval. With `gitOps.flux: true` the recipe sets
  `kustomize.toolkit.fluxcd.io/reconcile: disabled` on the target for the
  window and removes it on revert. This also excludes the object from prune
  during the window.
- Other controllers: the change drifts back within their interval; the
  recipe reports it as drift. A deployment that suspends the owning release
  must do so outside this recipe. Policy engines that own their webhook
configurations (for example Kyverno) re-assert `failurePolicy` when they are
healthy again; that counts as drift and is the desired end state.

## Security

- The requester never gets RBAC on the target objects.
- The spoke identity needs `get`/`patch` on the allowlisted kinds, which
  deployments can scope with `resourceNames`, and cluster-wide `list` on the
  same kinds for the restart sweep (`list` cannot be scoped by name).
- `deniedTargetSelector` is evaluated on the live object, so a policy that
  gains the protected label after the template was written is still refused.
- Audit: apply, revert, drift and refusal are synchronous durable audit
  events with requester, approver, target, original and applied value, like
  the node-maintenance receipts. Deployments can alert on them (for example a
  security operations rule on every `admission_recipe.applied`).

## Tests

- Unit: request validation (allowlist, duplicates, empty, unknown fields),
  apply/revert transitions per action, refusal on wrong starting value and
  denied labels, drift handling, idempotent revert.
- envtest: two sessions on the same target (second refused), revert at
  expiry, revert after simulated controller restart with only the spoke
  annotation left, revert skipped after drift.
- kind e2e: a webhook whose Service has no endpoints, recipe
  sets `Ignore`, Pod create succeeds, session terminate reverts to `Fail`;
  a Kyverno `ValidatingPolicy` switched to Audit and back, including Flux
  drift annotation handling.

## Alternatives considered

- **Cluster-admin escalation plus runbook.** No revert, no allowlist, no
  receipt. This is the current state.
- **Standing in-cluster reverter (CronJob).** Needs a second image and
  standing patch rights on the spoke, and cannot see the hub session state.
- **Auxiliary resources.** Create/delete only; a policy exception instead of
  an audit switch removes reporting entirely and is a broader change than the
  emergency needs.
