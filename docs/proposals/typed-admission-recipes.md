<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Proposal: typed admission recipes (policy audit switch, webhook fail-open)

Status: implemented (`DebugSessionTemplate.spec.admissionRecipe`). Target: a later 0.3.0 release candidate.

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

## API

The implementation follows this proposal; the user documentation is
[Typed admission recipes](../admission-recipes.md).

```yaml
# DebugSessionTemplate (administrator)
spec:
  constraints:
    maxDuration: 30m        # required, at most 2h; no idleTimeout, no renewal
  admissionRecipe:
    action: policy-audit    # or: webhook-fail-open
    flux: true              # see "GitOps controllers"
    allowedTargets:
      - {kind: ValidatingPolicy, apiVersion: policies.kyverno.io/v1, name: require-pod-probes}
    deniedTargetLabels:     # RE2, full label value; refused live even if allowlisted
      - {key: categories, valuePattern: '(.+_)?(platform-)?critical(_.+)?'}
```

```json
// POST /debugSessions (requester)
{
  "templateRef": "emergency-policy-audit",
  "cluster": "prod-cluster-01",
  "requestedDuration": "20m",
  "reason": "INC123: require-pod-probes blocks the hotfix rollout",
  "admissionRecipe": {"targets": [{"kind": "ValidatingPolicy", "apiVersion": "policies.kyverno.io/v1", "name": "require-pod-probes"}]}
}
```

Every requested target must equal an allowlist entry; duplicates, unknown
fields, generic workload inputs and empty lists are rejected. The action is
never a request field. A label *selector* was considered for denied targets,
but category labels such as `critical_psa_platform-best-practices` combine
several tokens in one value, so the denial is a full-match regular expression
per label key.

### Actions

| Action | Field transition | Revert |
| --- | --- | --- |
| `policy-audit` | Kyverno `ValidatingPolicy` (`policies.kyverno.io`): `spec.validationActions` that contains `Deny` → `[Audit]`. Legacy `ClusterPolicy` is out of scope. | Restore the recorded original list. |
| `webhook-fail-open` | `webhooks[name=<webhook>].failurePolicy` `Fail` (or unset, which means `Fail`) → `Ignore` on the named Validating/MutatingWebhookConfiguration. | Restore `Fail`. |

The recipe refuses a target whose current value is not the expected starting
value (already `Audit`/`Ignore`), and a target that another session's
annotation already owns.

## Lifecycle

1. **Approve.** Always an independent approver (the requester cannot approve
   in any stage, no auto-approval); binding approvers are captured
   immutably, as for `nodeMaintenance`.
2. **Apply** (session becomes Active). A revert finalizer is added first and
   a synchronous `applied` audit event is emitted before any write. For each
   target: re-read it, re-check denied labels, owner and starting value,
   persist `{original, applied, state: applying}` in `status.admissionRecipe`,
   re-validate the live session approval, then update the object with its
   read `resourceVersion`, setting the field and the annotations
   `breakglass.t-caas.telekom.com/admission-recipe-session` (session UID) and
   `.../admission-recipe-expires-at`.
3. **Watch.** Every 30 seconds each target is re-read. If the field or the
   session annotation changed, the target becomes `drifted`, a synchronous
   `drift` audit event is emitted and
   `breakglass_admission_recipe_operations_total{operation="drift"}`
   increases. The recipe never re-applies.
4. **Revert** on terminate, failure, hard expiry and deletion of the session
   (the finalizer holds the session until the revert is done). A target that
   still carries the session annotation and the applied value gets its
   original back; a drifted target keeps its value and only loses the
   annotations (`revert-skipped`). A synchronous `reverted` audit event
   follows. Failures are retried and stay visible in the `CleanupFailed`
   condition.
5. **Restart safety.** The hub status records the intent and original value
   before every write, and the spoke annotation shows whether the write
   happened. A restarted controller therefore marks an interrupted target
   applied or not-applied and reverts it; no cluster-wide sweep is needed.

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
- The spoke identity needs `get` and `update` on the allowlisted kinds, which
  deployments can scope with `resourceNames`.
- `deniedTargetLabels` is evaluated on the live object, so a policy that
  gains a protected label after the template was written is still refused.
- Audit: apply, revert, drift and refusal are synchronous durable audit
  events with requester, approver, target, original and applied value, like
  the node-maintenance receipts. Deployments can alert on them (for example a
  security operations rule on every `debug_session.admission_recipe.applied`).

## Example deployment (T-CaaS)

The T-CaaS platform decided these lists for its own templates:

- **policy-audit:** only non-critical Kyverno policies. Every policy whose
  `categories` label contains the token `critical` or `platform-critical`
  (the `platform-critical` and `critical` folders, for example
  `protect-platform-namespaces`, `protect-platform-resources`,
  `require-owner-label`, `disallow-host-path`, `disallow-host-namespaces`,
  `prevent-cr8escape`, `restrict-binding-clusteradmin`) is excluded by the
  allowlist and by `deniedTargetLabels` with
  `valuePattern: '(.+_)?(platform-)?critical(_.+)?'`.
- **webhook-fail-open:** allowed for the Kyverno resource validating and
  mutating webhooks, `ingress-nginx-admission`, the cert-manager validating
  webhook (never its mutating or conversion webhooks), the MetalLB and
  FRR-K8s validating webhooks, and the OpenTelemetry operator validation
  webhook. Never for the auth-operator namespace and binder webhooks, the
  Breakglass webhook, Cluster API and provider webhooks, CNI/IPAM/host
  network webhooks (coil, network-operator, netplan, whereabouts),
  vSphere CSI, or any mutating webhook.

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
- **Spoke-wide restart sweep.** Not needed: intent is persisted before each
  write and a finalizer holds the session until the revert.
- **Standing in-cluster reverter (CronJob).** Needs a second image and
  standing patch rights on the spoke, and cannot see the hub session state.
- **Auxiliary resources.** Create/delete only; a policy exception instead of
  an audit switch removes reporting entirely and is a broader change than the
  emergency needs.
