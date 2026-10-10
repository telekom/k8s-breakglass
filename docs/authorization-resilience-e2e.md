<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Authorization cache and webhook outage acceptance

The existing multi-cluster Kind suite now exercises two serial spoke-A cases:

* `TestCachedAuthorizationRevocation`: enables the apiserver webhook allow
  cache with a 20-second TTL, approves a session through the hub API, performs
  a real resource operation, drops through the requester API, observes a warm
  cached allow after revocation, then requires Forbidden within a bounded TTL.
* `TestWebhookOutageNoOpinionPreservesRBAC`: proves approved session access,
  configures the dedicated spoke webhook connection to a closed local port,
  disables caching, and verifies ordinary narrow RBAC access remains allowed
  while additional Breakglass access is Forbidden.

The authorizer contract is asserted as Node, RBAC, Webhook and NoOpinion.
NoOpinion is chain continuation, not grant-all. Admission webhook failure
policies are unrelated and remain unchanged.

Both tests rewrite the host-side source of the read-only Kind bind mounts,
restricted to regular fixture files inside this checkout. They restart only the
Kind spoke-A apiserver, restoring exact original authorization file bytes and
restarting again in cleanup. The shared hub remains
available. Do not run these methods concurrently or against a non-disposable
cluster. A network/setup error is not accepted as Forbidden evidence.

Use the repository's existing `e2e/kind-setup-multi.sh` environment and run:

```bash
E2E_MULTI_CLUSTER=true go test -tags=multicluster ./e2e/api \
  -run 'TestSpokeHubAuthorizationSuite/(TestCachedAuthorizationRevocation|TestWebhookOutageNoOpinionPreservesRBAC)$' \
  -count=1 -timeout=15m
```

The default multi-cluster CI selector includes these suite methods. No separate
deployment harness is introduced. The short TTL makes Kind execution bounded;
deployments with **positive authorization caching enabled** and five-minute
authorizedTTL still permit cached access for up to five minutes after revocation
or outage. When `cacheAuthorizedRequests: false`, that TTL is inactive; this test
explicitly opts into positive caching without changing production guidance.
Immediate authorization revocation
requires a different apiserver cache policy. Existing exec streams are a separate
lifecycle/termination concern.
