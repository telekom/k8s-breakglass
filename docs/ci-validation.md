# CI concurrency fixtures

The live-session fallback deduplication regression test starts a real manager lookup, waits until its live reader is blocked, then synchronously registers a second waiter with the manager's singleflight group before releasing the read. It checks that the result is shared, contains the expected session, and requires exactly one live read. Merely starting a second goroutine does not establish that it joined the pending lookup.

Run `go test -race -count=50 ./pkg/breakglass -run '^TestSessionManager_AuthorizationSelectionDeduplicatesLiveFallback$'` to check this scheduling boundary without sleep-based synchronization.
