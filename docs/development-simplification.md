<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Helper invariants

Namespace selectors use exact membership: `*` is literal, missing labels differ
from empty values, and deny rules take precedence. `GlobMatch` keeps its special
universal wildcard and exact-literal behavior. Approval-reason enrichment keeps
backend/stored reasons ahead of legacy lookups without mutating responses.

Unused frontend wrappers were removed; backend token validation and supported
session actions are unchanged. Run `go test ./pkg/utils` and
`cd frontend && npm test` for the affected helpers.

## Backend and frontend helpers

Exact membership uses `slices.Contains`, not wildcard matching. Map copies use
`maps.Clone`; helpers that previously normalized empty maps to `nil` retain that
behavior, and modifying a copied map must not modify its input. Both exported
RFC 1123 name normalizers retain their fallback, trimming, and 63/253-character
limits while sharing the normalization pipeline.

Import frontend date and duration utilities by their named exports rather than
constructing a stateless composable object. Pending-request withdrawals remain
in the view's confirmation/action flow, including busy state, error handling,
and pruning the completed request. Vite handles the literal dynamic imports used
by lazy routes and both UI flavours without an extra Rollup plugin.

## E2E helpers

Resource builders assign optional scalars and pointers directly. Defaults,
explicit `false`/zero pointers, and empty-slice normalization are unchanged.
`UpdateWithRetry` retries only update conflicts, re-fetches before reapplying
the modifier, and stops after six total attempts. Backoff starts at 50 ms,
doubles with a one-second cap, and remains cancellable through the context.

CI and the single-cluster setup share `e2e/lib/port-forward.sh`:

```bash
source e2e/lib/port-forward.sh
start_keepalive_port_forward breakglass-system breakglass-breakglass 8080 8080
```

An optional fifth argument selects a kubeconfig; otherwise the helper uses
`HUB_KUBECONFIG`, then `KUBECONFIG`. It preserves the two-second restart delay,
prints the wrapper PID, and records it when `PF_FILE` is set. Stopping the
wrapper also stops and reaps the active forwarder or restart-delay process.
Kubectl diagnostics are quiet by default; a sixth argument of `/dev/stderr`
duplicates the caller's stderr descriptor, preserving its capture and shared
file offset on Linux, as used by the hard-expiry workflow.
Endpoint-specific readiness checks remain with the callers.

Run `go test -race ./e2e/helpers`, `bash e2e/lib/port-forward_test.sh`, and
`shellcheck -x e2e/lib/port-forward.sh e2e/lib/port-forward_test.sh` for these
helper contracts. The shell test covers lifecycle behavior with a command
fixture; the normal CI E2E lanes remain the real Kubernetes forwarding proof.
