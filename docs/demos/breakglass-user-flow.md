# Breakglass user-flow recordings

The demo set contains three user-facing E2E recordings:

| Recording | Format | Focus |
| --- | --- | --- |
| [`breakglass-user-flow.cast`](./breakglass-user-flow.cast) | asciinema | `bgctl`, `kubectl auth whoami`, API access, and `tcpdump` in the spawned debug pod |
| [`breakglass-ui-browser-flow.webm`](./breakglass-ui-browser-flow.webm) | WebM | Standalone 4:3 browser request/approval/DebugSession workflow |
| [`breakglass-console-flow.cast`](./breakglass-console-flow.cast) | asciinema | Synchronized four-chapter `bgctl`/`kubectl` console track |
| [`breakglass-console-flow.webm`](./breakglass-console-flow.webm) | WebM | Standalone console screen recording |
| [`breakglass-ui-flow.webm`](./breakglass-ui-flow.webm) | WebM | 4:3 browser workflow synchronized beside the console track |
| [`breakglass-api-flow.cast`](./breakglass-api-flow.cast) | asciinema | REST API, authorization webhook, and DenyPolicy behavior |

The API/webhook recording covers:

1. A Kubernetes authorization webhook request is denied before approval.
2. The requester discovers an escalation and creates a `BreakglassSession`.
3. A separate approver approves the request through the REST API.
4. The same webhook request is allowed after approval.
5. A matching `DenyPolicy` still blocks access to secrets.
6. The requester reads the approved session through the API.
7. A developer discovers a debug template, creates a `DebugSession`, and reads
   its active state through the API.

The recordings use the existing single-cluster E2E environment. Temporary
sessions and resources are cleaned up when each run finishes. OIDC passwords
and bearer tokens are kept out of terminal output and are not captured.

## Play the CLI/API recordings

```bash
asciinema play docs/demos/breakglass-user-flow.cast
asciinema play docs/demos/breakglass-api-flow.cast
```

## Re-record the CLI/API recordings

The E2E Kind cluster must be running as `kind-breakglass-hub`, with the API
forwarded to `localhost:8080` and Keycloak forwarded to `localhost:8443`.

```bash
./e2e/record-breakglass-cli-demo.sh
./e2e/record-breakglass-demo.sh
```

The runners load `e2e/kind-setup-single-tdir/e2e-env.sh` automatically. The CLI
recording uses Kubernetes impersonation for `kubectl auth whoami` and
`kubectl auth can-i` because the reusable Kind API server does not accept the
external Keycloak bearer token directly; the `bgctl` calls still use the real
OIDC token.

## Re-record the UI recording

```bash
./e2e/record-breakglass-ui-demo.sh
```

The UI runner uses the real Keycloak-backed Playwright E2E flow at a 4:3
viewport, adds visible step explainers to the browser segments, slows playback
to 0.5x, and produces standalone browser and console recordings plus a
chapter-synchronized composite without letterboxing.

If the forwards are not already running, select the E2E Kind context and start
the repository helper first:

```bash
kubectl config use-context kind-breakglass-hub
./e2e/setup-e2e-env.sh --all
```

Set `KUBECTL_CONTEXT`, `BREAKGLASS_DEMO_RECORDING`, `BREAKGLASS_CLI_DEMO_RECORDING`,
`BREAKGLASS_UI_DEMO_RECORDING`, `BREAKGLASS_DEMO_PAUSE`,
`BREAKGLASS_RECORD_UI_PAUSE_MS`, `BREAKGLASS_UI_SLOWDOWN`,
`BREAKGLASS_UI_BROWSER_RECORDING`, `BREAKGLASS_CONSOLE_DEMO_RECORDING`, or
`BREAKGLASS_CONSOLE_VIDEO_RECORDING`, or `BREAKGLASS_TERMINAL_SPEED` to
override the defaults.
