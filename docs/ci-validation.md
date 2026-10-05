# CI concurrency fixtures

The live-session fallback deduplication regression test starts a real manager lookup, waits until its live reader is blocked, then synchronously registers a second waiter with the manager's singleflight group before releasing the read. It checks that the result is shared, contains the expected session, and requires exactly one live read. Merely starting a second goroutine does not establish that it joined the pending lookup.

Run `go test -race -count=50 ./pkg/breakglass -run '^TestSessionManager_AuthorizationSelectionDeduplicatesLiveFallback$'` to check this scheduling boundary without sleep-based synchronization.

## Remote cluster client characterization

Run `make test-cluster-clients` for the real-API safety net before changing
`pkg/cluster` credential loading, client caching, or invalidation. The target
downloads the pinned envtest version, exports an absolute `KUBEBUILDER_ASSETS`,
and runs in the controller unit-test CI job. Plain unit tests skip the real-API
test when assets are absent; this dedicated CI target does not.

`TestClientProviderRealAPI` creates a manager and actual Secret/ClusterConfig
informers. It verifies Secret-backed clients reach the API server, shared-Secret
rotation/deletion evicts REST configs, clientsets and bare-name aliases,
ClusterConfig reference changes/deletion remove dependencies, and concurrent
refresh cannot repopulate the cache after invalidation completes. Privileged
client tests fence Secret and inherited IdentityProvider resource versions,
ClusterConfig versions, specs and UIDs, including credential rotation during
construction, without relying on watchers. Ambiguous bare names fail closed
both on live list results and cached matches; explicit namespace keys still work.
The OIDC path uses real Kubernetes Secrets and a TLS issuer/spoke fixture to
verify token injection, client-secret and CA dependency invalidation, and refusal
to send a cached token after credentials are deleted. Configuration construction
can succeed after deletion; the OIDC transport reports the credential error.

Circuit-breaker lifecycle tests assert open/half-open/closed metrics, rejection
counters, per-cluster isolation, transient-error classification and stale
generation completion fencing. These characterization tests remain unchanged
during the registry migration.

The repository uses Go `testing` selectors, not Ginkgo labels, for these E2Es.
The existing `multi-cluster-e2e` CI lane runs `go test -tags=multicluster
./e2e/api/...` with `E2E_TEST=true` and `E2E_MULTI_CLUSTER=true`, covering
`TestClusterConfigConnectivity`, `TestCrossClusterSARAuthorization`,
`TestMultiClusterConfiguration`, `TestCrossClusterEscalation` and
`TestHubSpokeSuite`. The OIDC lane also covers `TestClusterConfigOIDCAuthentication`,
`TestClusterConfigOIDCStatusConditions`, `TestClusterConfigOIDCWithEscalation`,
inherited IdentityProvider credentials and comprehensive token-renewal/fallback
flows. Keep these selectors and environment gates enabled during migration.

### Registry adoption and compatibility

Kubeconfig-backed clients now use
[`t-caas-go-library/pkg/remoteclient`](https://github.com/telekom/t-caas-go-library/tree/v0.1.0/pkg/remoteclient)
at `v0.1.0` for construction, credential dependencies and eviction. The provider
retains REST-config/clientset TTLs, aliases, OIDC token/Secret tracking, metrics
and live privileged-input fences. Registry callbacks run synchronously under
the provider lock; they clear the local caches without taking that lock again.
Privileged operations still rebuild between live snapshots and reuse only the
registry client associated with that exact rebuilt REST config.

The library validates transports eagerly. To preserve the previous REST-config
API, parseable configs with invalid TLS material can still be returned without a
client; native `clientcmd` parsing remains the compatibility fallback. The
registry retains their pending Secret dependency, and privileged calls cannot
fall back to an older valid client after a failed refresh. Returned clients are
not revoked by invalidation: callers must retain their final live fences.

**Security tightening:** Secret kubeconfigs must be self-contained. Embed CA,
client certificate/key or bearer-token data. Exec/auth-provider plugins, token
files and filesystem certificate/key/CA references are rejected, including
unused entries in the kubeconfig. Errors do not include credential/parser
details. `TestKubeconfigRegistryRequiresEmbeddedCredentials` pins this contract;
the other registry tests pin client association and lazy TLS-error behavior.

The [upstream-first guide](https://github.com/telekom/t-caas-go-library/blob/main/docs/upstream-libraries.md)
still applies to circuit breakers. Audit already uses `sony/gobreaker/v2`.
The cluster breaker's shared epoch-based completion contract and independent
half-open concurrency/success thresholds do not map directly to gobreaker's
per-admission completion callbacks and `MaxRequests`; replacing it would require
additional local admission bookkeeping. It remains unchanged rather than
introducing a second breaker engine or changing the characterized semantics.
