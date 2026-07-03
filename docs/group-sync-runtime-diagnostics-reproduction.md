# Group Sync Runtime Diagnostics Reproduction

This branch is reproduce-only. It documents two runtime diagnostics gaps seen
during the T-CaaS rollout investigation and adds failing tests without changing
controller behavior.

## Reproduced Gaps

1. Keycloak group search `403` returns the raw client error.

   The controller logs include endpoint and parameter context, but
   `KeycloakGroupMemberResolver.Members` returns only `403 Forbidden`. Operators
   need the returned error to include the Keycloak groups endpoint and the
   permission hint for the service account, for example `view-users`.

2. `GroupFetchFailed` is emitted for a cluster-scoped `IdentityProvider` object
   with an empty namespace.

   The low-level Kubernetes event recorder has namespace fallback coverage, but
   the updater call path currently creates a synthetic `IdentityProvider` with
   only a name and passes it to `Eventf`. This reproduces the empty
   involved-object namespace observed in rollout logs.

## Reproduction Command

Run the focused tests with localhost sockets available:

```sh
GOCACHE=/tmp/k8s-breakglass-repro-go-cache go test ./pkg/breakglass/escalation \
  -run 'TestKeycloakGroupMemberResolver_Members_GroupSearchForbiddenIsActionable|TestFetchGroupMembersFromMultipleIDPs_GroupFetchFailedEventHasNamespace' \
  -count=1
```

Expected result on this branch: both tests fail.

## Existing Upstream Coverage Not Duplicated

Current `origin/main` already removed stale event text that pointed operators to
`status.groupSyncErrors`, and `BreakglassEscalationStatus` still has no such
field. That gap is not reproduced here because it appears to be fixed upstream
and only present in older rolled-out versions.

The existing event recorder tests cover generic namespace fallback behavior.
This branch specifically reproduces the updater call path that passes a
cluster-scoped `IdentityProvider` object to the recorder.
