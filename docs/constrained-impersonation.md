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

| Spoke version | Gate | Constrained RBAC applied | Detected capability | Impersonation used | RBAC needed |
|---|---|---|---|---|---|
| ≤ 1.34 | absent | either | unsupported (version floor, no probe) | legacy | `impersonate_role.yaml` |
| 1.35 | off (default) | either | unsupported (probe denied) | legacy | `impersonate_role.yaml` |
| 1.35 | on (opt-in) | no | unsupported (probe denied) | legacy | `impersonate_role.yaml` |
| 1.35 | on (opt-in) | yes | **supported** | constrained | both files |
| 1.36+ | on (default) | no | unsupported (probe denied) | legacy | `impersonate_role.yaml` |
| 1.36+ | on (default) | yes | **supported** | constrained | both files |
| 1.36+ | off (explicit) | either | unsupported (probe denied) | legacy | `impersonate_role.yaml` |
| any | any | either, version unreadable | unsupported | legacy | `impersonate_role.yaml` |

### How detection actually works, and why the obvious approach cannot

This deserves spelling out, because the intuitive design is silently broken.

KEP-5284 adds **no new headers**. Client-side semantics are deliberately unchanged,
and the API server derives the mode from the *shape* of the impersonated identity.
Two consequences follow:

1. An ordinary impersonated request is **byte-identical** on the wire whether or not
   the spoke supports constrained impersonation.
2. The API server **falls back to legacy** whenever every constrained mode denies, so
   the deliberately-retained blanket `impersonate` grant authorizes the request
   either way.

Therefore *"the impersonated request succeeded"* is **not evidence of constrained
support**. Concluding support from it would mark every legacy-granted spoke
"supported" at any version with the gate in any state — and because the fallback
branch would never be reached, `legacy_fallback_total` would stay at zero too. Both
signals in the retirement criteria below would read green on a spoke with no
constrained support at all.

Breakglass therefore combines **two independent signals**, and requires *both*
before claiming support:

- **A version floor.** Constrained impersonation cannot exist before 1.35, so such a
  spoke is settled with no probe at all. This is the only place a Kubernetes version
  is compared (`impersonation.VersionHint`), and an unreadable or unparseable version
  yields *unsupported*, never *supported*.
- **A discriminating probe.** The probe impersonates a synthetic **UID**
  (`breakglass-capability-probe`) alongside the probe username, which forces the API
  server to authorize a `uids` identity check in the `authentication.k8s.io` API
  group. The legacy grant covers `users` and `groups` in the **core** group and
  provably cannot satisfy that check, so the legacy fallback cannot rescue this
  probe. Success is positive proof that a constrained mode genuinely ran.

This is what makes the "accepted but inert" case behave correctly: applying the
constrained ClusterRole to a pre-1.35 spoke confers nothing, and an inert grant
cannot authorize the probe, so the spoke is still correctly reported unsupported.

Four rules keep this safe:

- **Support is never claimed on ambiguous evidence.** Anything short of positive
  proof reports *unsupported* or *unknown*, both of which keep the legacy grant in
  use. Under-claiming is the safe direction.
- **Unknown capability still attempts the constrained path**, then falls back, so a
  wrong first guess costs one extra denied `SelfSubjectAccessReview`, not an outage.
- **Only a clean authorization answer settles a spoke.** A network error, timeout or
  unrelated 500 leaves capability *undetermined and uncached*, so a transient blip
  cannot pin a spoke to legacy.
- **Capability is re-detected every 10 minutes**, and a ClusterConfig change
  invalidates the record immediately, so flipping the gate or the `support:` setting
  takes effect without restarting the controller.

### Known limitation of the probe

The discriminator assumes a spoke's legacy grant does **not** itself cover
`authentication.k8s.io` `uids`. If breakglass is bound to `cluster-admin` on a spoke,
or to any role broad enough to include that resource, the probe can report
*supported* on a spoke where constrained impersonation is not really in force.

Such a spoke still **works** — constrained is attempted and the legacy fallback
covers it — but its capability gauge cannot be trusted on its own. This is exactly
why the retirement procedure below requires manual verification and an explicit
operator assertion, and never keys off the gauge alone.

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

> **`Forbidden` does not override an RBAC allow.** It only affects requests that
> actually reach the breakglass webhook. See
> *What this does and does not protect* below — this matters a great deal if you are
> relying on `Forbidden` to stop legacy impersonation.

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

### Retiring the legacy grant on a spoke

> **No metric combination is sufficient on its own to authorize this.** Read the
> reasoning before following the steps — this procedure removes the grant that
> breakglass falls back to, and getting it wrong means breakglass stops authorizing
> anyone on that spoke.

The metrics are necessary but **not sufficient**:

```promql
# NECESSARY, NOT SUFFICIENT — see the caveats below.
breakglass_impersonation_capability{cluster="my-spoke", support="supported"} == 1
rate(breakglass_impersonation_legacy_fallback_total{cluster="my-spoke"}[1h]) == 0
```

Why they cannot be trusted alone:

- `capability{support="supported"}` can be a false positive on a spoke where
  breakglass holds an over-broad grant (see *Known limitation of the probe* above).
- `legacy_fallback_total` counts what the **webhook** saw. The webhook sits *after*
  RBAC in the authorizer chain, so a legacy impersonation that RBAC already allowed
  never reaches breakglass and is never counted. A flat counter therefore does not
  prove the legacy path is unused.

**Manual verification procedure.** Do all of these on the specific spoke:

1. **Confirm the gate is really on**, from the spoke's own API server rather than
   from a version number:
   ```bash
   kubectl get --raw='/metrics' \
     | grep apiserver_impersonation_authorization_attempts_total
   ```
   Series with `mode="user-info"` prove the constrained code path is executing. No
   `impersonation` series at all means the gate is off — **stop here.**

2. **Confirm the constrained RBAC is present and effective**, using a
   SubjectAccessReview issued as breakglass's own ServiceAccount:
   ```bash
   kubectl auth can-i --as=system:serviceaccount:breakglass-system:manager \
     impersonate:user-info uids.authentication.k8s.io
   ```
   This must answer `yes`. It is the same check detection relies on, and the legacy
   grant cannot satisfy it.

3. **Confirm the grant is not load-bearing elsewhere.** Enable spoke audit at
   `Metadata` or higher and confirm that over a full business cycle — including an
   actual breakglass session and a debug session — every impersonated request
   carries a constraint:
   ```
   authenticationMetadata.impersonationConstraint: "impersonate:user-info"
   ```
   An **absent** field on an impersonated request means that request used legacy
   impersonation and would break. This is the only signal that covers requests the
   webhook never sees.

4. **Assert capability explicitly** rather than relying on detection, so the spoke
   cannot silently revert to a probe verdict:
   ```yaml
   spec:
     constrainedImpersonation:
       support: Enabled
   ```

5. **Then, and only then**, remove `impersonate_role.yaml`'s ClusterRole from that
   spoke and set `legacyFallback: Forbidden`.

6. **Have a rollback ready.** Re-applying `impersonate_role.yaml` restores service
   immediately; keep it to hand for the first few spokes.

Do steps 1–6 **one spoke at a time**. Capability is per-spoke, and so is the blast
radius.

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

## What this does and does not protect

The breakglass webhook's impersonation controls are real, but they are narrower than
they read, because of **where the webhook sits**. Knowing the boundary matters before
you rely on any of them.

The spoke's authorizer chain is `Node → RBAC → Webhook(breakglass)`. The webhook is
**last**, and the chain short-circuits on the first allow.

### `legacyFallback: Forbidden` cannot override an RBAC allow

If RBAC already allows a legacy impersonation — which is exactly what a blanket
`impersonate` ClusterRole does — the API server never consults breakglass, so
`Forbidden` is never evaluated and the impersonation proceeds. `Forbidden` takes
effect **only for requests that reach the webhook**.

This is not a bug to be fixed by reordering the chain: placing a webhook before RBAC
would route every authorization decision in the cluster through breakglass, making it
a hard dependency for all cluster traffic. That is the wrong trade for an
emergency-access tool.

What `Forbidden` *is* good for:

- Denying legacy impersonation that RBAC does **not** already allow, i.e. attempts
  that would otherwise be decided by a breakglass session.
- A tripwire and a statement of intent, recorded in
  `breakglass_impersonation_legacy_fallback_total{outcome="denied"}`.

**To actually prevent legacy impersonation you must remove the legacy grant.** There
is no webhook setting that substitutes for it — follow *Retiring the legacy grant on
a spoke* above. Set `Forbidden` in addition, so a re-introduced grant is denied
loudly for the paths the webhook does see.

### System principals are excluded by `matchConditions`

The recommended webhook configuration skips `system:*` users and service accounts:

```yaml
matchConditions:
- expression: "'system:authenticated' in request.groups"
- expression: "!request.user.startsWith('system:')"
- expression: "!('system:serviceaccounts' in request.groups)"
```

This is deliberate and load-bearing — breakglass's own RBAC probe runs as a
ServiceAccount, so without it the controller could deadlock on itself. The
consequence is that the `system:masters` guardrail and the unrecognised-verb denial
do **not** apply to ServiceAccount-originated impersonation. Constrain service
accounts with RBAC; the webhook is not the control point for them.

### What does hold unconditionally

- The API server's own hard-deny of `system:masters` in **constrained** modes, which
  needs no webhook.
- Admission-time validation of `impersonation` blocks on templates and bindings,
  which runs before anything is stored.
- The webhook's denials, for every request that reaches it: unrecognised verbs,
  `system:masters` by name, wildcard group checks, and `DenyPolicy` rules.

## Upgrade impact

Upgrading to this version changes **no** cluster behaviour and requires no operator
action. One observable thing does change.

**Some spokes move from `support="supported"` to `support="unsupported"`.** Earlier
builds concluded support from the success of an ordinary impersonated request, which
every spoke holding the legacy grant satisfies regardless of version or gate state.
That verdict was wrong; the new verdict is correct. Expect
`breakglass_impersonation_capability{support="unsupported"} == 1` on every spoke that
is below 1.35, has the gate off, or has not had
`config/rbac/impersonate_constrained_role.yaml` applied.

What this means in practice:

- **Authorization behaviour is unchanged.** Those spokes were already being served by
  legacy impersonation — that is what made the old verdict wrong. They keep the
  legacy grant and keep working byte-identically.
- **Dashboards and alerts that assert `support="supported"` will start firing** for
  affected spokes. Update them: the new value is the truthful one.
- **If you already retired a legacy grant on the strength of the old metric**, check
  that spoke now. If it reports `unsupported` while the grant is gone, breakglass
  cannot authorize on it — re-apply `impersonate_role.yaml` and then follow the
  verification procedure above.
- **To move a spoke to `supported`,** apply
  `config/rbac/impersonate_constrained_role.yaml` (additive and safe at any version)
  and ensure the spoke is 1.35+ with the gate on. The role now also grants the
  `uids` identity check that detection requires, so **re-apply it** if you deployed
  an earlier revision of this branch.

No CRD field is added or changed by this fix, and no stored object needs migration.

## Not configurable

Fixed by the API server and not exposed: the authorization cache TTL (10s), the
wildcard-collapse threshold (4), header names, verb spellings, and the forced group
lists for node (`system:nodes`) and ServiceAccount identities.

## See also

- [`cluster-config.md`](cluster-config.md) — per-spoke `constrainedImpersonation`
- [`deny-policy.md`](deny-policy.md) — `impersonationRules`
- [`debug-session.md`](debug-session.md) — `impersonation` on templates and bindings
- [`security-best-practices.md`](security-best-practices.md) — migration guidance
