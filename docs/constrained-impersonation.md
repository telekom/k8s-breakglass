<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Constrained Impersonation (KEP-5284)

Kubernetes 1.35 introduced **constrained impersonation**, which replaces the
all-or-nothing `impersonate` verb with grants that are scoped to a specific
identity *and* a specific set of actions. It became beta and **on by default in
1.36**.

Breakglass supports it on three fronts:

1. Its **authorization webhook** recognises, evaluates and can explicitly deny the
   new verbs. This closes a security gap — see below.
2. **DenyPolicy** can target impersonation directly, including the legacy fallback.
3. Its own RBAC probe and debug-session deployments use constrained impersonation
   where the spoke supports it, falling back to legacy where it does not.

## The security gap this closes

The API server authorizes constrained impersonation by asking the authorizer chain
about verbs that did not exist before 1.35:

| Verb family | Example | Purpose |
|---|---|---|
| identity | `impersonate:user-info` | May this requestor impersonate this identity? |
| action | `impersonate-on:user-info:list` | May this requestor `list` under impersonation? |

Both checks must pass, and the action check runs first.

The problem: **an authorization webhook that allows verbs it does not recognise
silently grants constrained impersonation.** On any 1.36 cluster — where the gate
is on by default — the API server asks breakglass about `impersonate:<mode>` verbs.
A webhook with no notion of them may return an allow for reasons that have nothing
to do with impersonation, and the API server treats that as a considered decision.

Breakglass therefore **fails closed** on any impersonation verb it cannot parse.
This is deliberately scoped to impersonation verbs only, so it cannot affect
ordinary requests. Watch:

```promql
# Should be zero. Non-zero means breakglass is older than a spoke's API server.
breakglass_impersonation_unrecognised_verbs_total
```

Opt out per spoke with `spec.constrainedImpersonation.denyUnrecognisedVerbs: false`
only while debugging a newer API server against an older breakglass.

## Compatibility: the per-spoke version matrix

Breakglass is hub-and-spoke, and the hub and each spoke can run **different**
Kubernetes versions. Capability is therefore resolved **per spoke** and cached — it
is never inferred from the hub's own version, and two spokes at different versions
work simultaneously in one controller.

| Spoke version | Gate | Detected capability | Impersonation used | RBAC needed |
|---|---|---|---|---|
| ≤ 1.34 | absent | unsupported (after first probe) | legacy | `impersonate_role.yaml` |
| 1.35 | off (default) | unsupported (after first probe) | legacy | `impersonate_role.yaml` |
| 1.35 | on (opt-in) | supported | constrained | both files |
| 1.36+ | on (default) | supported | constrained | both files |
| 1.36+ | off (explicit) | unsupported (after first probe) | legacy | `impersonate_role.yaml` |

Detection **probes rather than compares versions**. The RBAC probe in
`pkg/breakglass` attempts the constrained path and observes the outcome, because a
version string cannot tell you whether an operator disabled the gate. A version
comparison exists only as an advisory hint (`impersonation.VersionHint`) that
decides which path to try first, never whether a path is permitted.

Three rules keep this safe:

- **Unknown capability attempts the constrained path**, then falls back. A wrong
  first guess costs one extra denied `SelfSubjectAccessReview`, not an outage.
- **Only an impersonation *denial* downgrades a spoke.** A network error or an
  unrelated 500 is propagated, so a transient blip cannot pin a spoke to legacy.
- **Capability is re-detected every 10 minutes**, so enabling the gate on a spoke
  takes effect without restarting the controller.

## Modes

The mode is **not** a header. KEP-5284 adds no headers; the API server derives the
mode from the shape of the impersonated identity.

| Mode | Selected when |
|---|---|
| `associated-node` | user is `system:node:<name>`, only username set, requestor's own node matches |
| `arbitrary-node` | user is `system:node:<name>`, only username set, valid DNS subdomain |
| `serviceaccount` | user is `system:serviceaccount:<ns>:<name>`, only username set |
| `user-info` | user is neither a node nor a ServiceAccount; the only mode supporting uid/groups/extra |
| `legacy` | fallback when every constrained mode denies |

## Footguns

### The header-mixing trap

**Sending `uid`, `groups` or `extra` alongside a ServiceAccount or node username
silently disables constrained impersonation.**

The node and `serviceaccount` modes require that *only* the username be set. Add
anything else and the API server skips those modes, falls through `user-info`
(which refuses node and SA usernames), and lands on **legacy** — where none of the
constrained restrictions apply. The request may still succeed via a blanket
`impersonate` grant, with nothing in the audit log to say the constraint was lost.

Breakglass rejects this combination at admission, via both CEL and Go validation:

```yaml
# REJECTED
impersonation:
  mode: serviceaccount
  serviceAccountRef: {name: deployer, namespace: breakglass-debug}
  uid: "abc"   # <-- would silently disable constrained mode
```

### The legacy fallback defeats your constraints

A blanket `impersonate` grant on core `users`/`groups` with no `resourceNames`
**wins by fallback**. Where a spoke supports constrained impersonation, keeping such
a grant makes every constraint decorative. Worse, the API server does *not* apply
the constrained restrictions to the legacy path — including the `system:masters`
hard-deny.

Breakglass closes this in two ways. It refuses `system:masters` impersonation in
*every* mode, legacy included. And `legacyFallback: Forbidden` denies the legacy
verb outright on a given spoke:

```yaml
spec:
  constrainedImpersonation:
    legacyFallback: Forbidden
```

A `DenyPolicy` rule that lists only constrained modes accomplishes nothing while a
legacy grant exists. Always include `legacy`:

```yaml
impersonationRules:
- modes: [user-info, serviceaccount, arbitrary-node, associated-node, legacy]
  identityResources: [groups]
  identities: ["cluster-admins"]
```

### Grants union, they do not correlate

Granting two identities and two actions grants the **cross product**. There is no
way to express "user A only for pods AND user B only for secrets" in one rule set;
split it into separate configurations. Breakglass emits an admission warning when a
configuration would produce a cross product.

### The wildcard-collapse threshold

At **four or more** items the API server collapses per-item identity checks into a
single `*` wildcard check. Grants naming individual groups then stop being
consulted. This is hardcoded and not configurable.

Breakglass handles the security consequence: a `DenyPolicy` naming specific
identities also matches the collapsed `*` check, so requesting four identities at
once cannot evade a policy. It warns when a configuration lists four or more
groups.

### No prefix wildcard on action verbs

You cannot write `impersonate-on:user-info:*`. RBAC `verbs: ["*"]` does match, but
there is no prefix form. Use a bare `"*"` in `actionVerbs`; anything else
containing `*` never matches, and breakglass warns about it.

## RBAC migration

`config/rbac/` ships **two** files, and this is deliberate:

| File | Mode | Apply to |
|---|---|---|
| `impersonate_role.yaml` | legacy | every spoke (unchanged) |
| `impersonate_constrained_role.yaml` | `user-info` | every spoke (additive, inert where unsupported) |

The constrained file is safe on **any** version. On a spoke without the feature its
rules are accepted but inert, because RBAC verbs and resources are free-form
strings — nothing errors, the grant just confers nothing.

**That is also why the legacy grant must not be removed unconditionally.** Strip it
from a pre-1.35 spoke and the group-checker probe stops working, so breakglass
silently stops authorizing anyone: a total outage presented as a successful rollout.

To retire the legacy grant on a spoke, confirm it is no longer used:

```promql
breakglass_impersonation_capability{cluster="my-spoke", support="supported"} == 1
rate(breakglass_impersonation_legacy_fallback_total{cluster="my-spoke"}[1h]) == 0
```

Then remove the ClusterRole from that spoke *and* set
`legacyFallback: Forbidden` on its ClusterConfig, so a regression is denied loudly
rather than silently downgraded.

## Observability

### Breakglass metrics

| Metric | Labels | Use |
|---|---|---|
| `breakglass_impersonation_sar_requests_total` | cluster, mode, verb_kind | Traffic by mode |
| `breakglass_impersonation_sar_decisions_total` | cluster, mode, decision, source | Decisions |
| `breakglass_impersonation_unrecognised_verbs_total` | cluster, outcome | **Alert on this** |
| `breakglass_impersonation_legacy_fallback_total` | cluster, outcome | Migration progress |
| `breakglass_impersonation_capability` | cluster, support | Per-spoke capability |
| `breakglass_impersonation_downgrades_total` | cluster, requested_mode | Constrained → legacy |
| `breakglass_impersonation_deny_policy_errors_total` | cluster | Fail-closed evaluations |

### API server audit

The API server records the identity verb in a new top-level audit field:

```json
{"authenticationMetadata": {"impersonationConstraint": "impersonate:user-info"}}
```

It is **omitted for legacy impersonation** — an absent field on an impersonated
request means the constraint was not applied. Requires audit policy level
`Metadata` or higher.

Breakglass mirrors the same value in its own `resource.impersonate` audit events as
`details.impersonationConstraint`, so the two trails can be joined per request.

### API server metrics

Subsystem `impersonation`, labels `{mode, decision}` (ALPHA stability):
`apiserver_impersonation_attempts_total`,
`apiserver_impersonation_attempts_duration_seconds`,
`apiserver_impersonation_authorization_attempts_total`,
`apiserver_impersonation_authorization_attempts_duration_seconds`.

## Caveat: UnconditionalAuthorizer

Constrained impersonation requires an `authorizer.UnconditionalAuthorizer` and is
incompatible with conditional or field-selector-returning authorizers.

Breakglass's webhook **satisfies this**. It returns only `allowed` and `reason` in
its `SubjectAccessReview` response — never `conditions` or field/label selectors —
so from the API server's perspective it is unconditional. No change is required to
use breakglass alongside constrained impersonation.

## Not configurable

Fixed by the API server and not exposed: the authorization cache TTL (10s), the
wildcard-collapse threshold (4), header names, verb spellings, and the forced group
lists for node (`system:nodes`) and ServiceAccount identities.

## See also

- [`cluster-config.md`](cluster-config.md) — per-spoke `constrainedImpersonation`
- [`deny-policy.md`](deny-policy.md) — `impersonationRules`
- [`debug-session.md`](debug-session.md) — `impersonation` on templates and bindings
- [`security-best-practices.md`](security-best-practices.md) — migration guidance
