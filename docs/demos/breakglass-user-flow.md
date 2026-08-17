# Breakglass user-flow recording

`breakglass-user-flow.cast` is an asciinema recording of the user-facing E2E
journey:

1. A Kubernetes authorization webhook request is denied before approval.
2. The requester discovers an escalation and creates a `BreakglassSession`.
3. A separate approver approves the request through the REST API.
4. The same webhook request is allowed after approval.
5. A matching `DenyPolicy` still blocks access to secrets.
6. The requester reads the approved session through the API.
7. A developer discovers a debug template, creates a `DebugSession`, and reads
   its active state through the API.

The recording uses the existing single-cluster E2E environment. It creates
one temporary `BreakglassEscalation` for the demo and cleans up the escalation
and sessions when the run finishes. OIDC passwords and bearer tokens are kept
out of the terminal output and are not captured.

## Play the recording

```bash
asciinema play docs/demos/breakglass-user-flow.cast
```

## Re-record it

The E2E Kind cluster must be running as `kind-breakglass-hub`, with the API
forwarded to `localhost:8080` and Keycloak forwarded to `localhost:8443`.

```bash
./e2e/record-breakglass-demo.sh
```

The runner loads `e2e/kind-setup-single-tdir/e2e-env.sh` automatically.

If the forwards are not already running, select the E2E Kind context and start
the repository helper first:

```bash
kubectl config use-context kind-breakglass-hub
./e2e/setup-e2e-env.sh --all
```

Set `KUBECTL_CONTEXT` or `BREAKGLASS_DEMO_RECORDING` to override the default
cluster context or output path.
