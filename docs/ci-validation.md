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
client tests fence Secret resource versions, ClusterConfig versions and UIDs,
including credential rotation during construction, without relying on watchers.
The OIDC path uses real Kubernetes Secrets and a TLS issuer/spoke fixture to
verify token injection, client-secret and CA dependency invalidation, and refusal
to send a cached token after credentials are deleted. Configuration construction
can succeed after deletion; the OIDC transport reports the credential error.

Circuit-breaker lifecycle tests assert open/half-open/closed metrics, rejection
counters, per-cluster isolation, transient-error classification and stale
generation completion fencing. No production code or dependencies change.

The repository uses Go `testing` selectors, not Ginkgo labels, for these E2Es.
The existing `multi-cluster-e2e` CI lane runs `go test -tags=multicluster
./e2e/api/...` with `E2E_TEST=true` and `E2E_MULTI_CLUSTER=true`, covering
`TestClusterConfigConnectivity`, `TestCrossClusterSARAuthorization`,
`TestMultiClusterConfiguration`, `TestCrossClusterEscalation` and
`TestHubSpokeSuite`. The OIDC lane also covers `TestClusterConfigOIDCAuthentication`,
`TestClusterConfigOIDCStatusConditions`, `TestClusterConfigOIDCWithEscalation`,
inherited IdentityProvider credentials and comprehensive token-renewal/fallback
flows. Keep these selectors and environment gates enabled during migration.
