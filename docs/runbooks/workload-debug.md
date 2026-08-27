<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Workload-debug image runbook

`ghcr.io/telekom/k8s-breakglass/utils/workload-debug` is a generic, standalone toolbox
for a short-lived DebugSession or an ordinary workload Pod. It has no
dependency on `DebugSession` labels, annotations, namespace names, or the
Breakglass controller. It runs as UID/GID `65532`, has no Linux capabilities,
and is designed for a read-only root filesystem.

## Build and attest

Build from the image directory so the Dockerfile and its license bundle are
available in the build context:

```sh
cd utils/workload-debug
docker buildx build --platform linux/amd64,linux/arm64 \
  --file Dockerfile \
  --tag ghcr.io/telekom/k8s-breakglass/utils/workload-debug:0.1.0 --push .
```

Use the exact digest in `utils/workload-debug/IMAGE-METADATA.yaml`; do not
publish or deploy a mutable `latest` tag. Generate and retain an SPDX SBOM,
then sign the digest with the keyless Cosign commands in that metadata file.

## Direct Docker or Podman use

The default command opens a shell. `--read-only` is supported because bounded
response buffering uses only a private ephemeral directory. The helper
prefers `TMPDIR`, then `/dev/shm`, then `/tmp`; mount a small tmpfs explicitly
when the runtime does not provide a writable ephemeral directory:

```sh
docker run --rm -it --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  ghcr.io/telekom/k8s-breakglass/utils/workload-debug@sha256:DIGEST
docker run --rm -it --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  ghcr.io/telekom/k8s-breakglass/utils/workload-debug@sha256:DIGEST
podman run --rm -it --read-only --cap-drop=all \
  ghcr.io/telekom/k8s-breakglass/utils/workload-debug@sha256:DIGEST
```

For Podman, the same image can be run with `--user 65532:65532`; it is already
the image default.

## Kubernetes Pod and DebugSession

The image can be used as a normal Pod or as the `image` in a
`DebugPodTemplate`. Keep the security context explicit when the admission
policy permits it:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
  seccompProfile:
    type: RuntimeDefault
```

The default interactive shell can invoke packaged binaries directly; helper
allowlists are not an authorization boundary. Provider-owned RBAC,
NetworkPolicy, immutable image/security-context fields, and the session
lifetime must enforce the chosen intent. Do not expose credentials or network
destinations that the session does not require.

The Kubernetes helper uses the standard service-account CA and token files
when they are mounted. Outside a Kubernetes Pod, pass `--server`; no
controller metadata is inferred:

```sh
workload-debug dns api.example.test
workload-debug tls api.example.test:443
workload-debug http https://api.example.test/healthz
workload-debug kube-api --server https://api.example.test /version
workload-debug report --dns api.example.test --tls api.example.test:443
```

HTTP and Kubernetes API requests are deliberately bounded: only GET, HEAD, and
OPTIONS are accepted, redirects are not followed, and responses are limited to
1 MiB by default. `WORKLOAD_DEBUG_TIMEOUT` accepts 1–300 seconds and
`WORKLOAD_DEBUG_MAX_BYTES` accepts 1–10 MiB when a different bounded limit is
needed.
DNS and TLS diagnostics use the same timeout and cap combined command output
at 64 KiB by default. Set `WORKLOAD_DEBUG_MAX_OUTPUT_BYTES` to a value from 1
byte through 1 MiB for a different bounded limit. If the deployment mounts
the optional internal runbook volume, its index is available at
`/usr/share/breakglass/runbooks/internal/INDEX.md`; it is documentation only
and is never sourced. The bundle root is mounted directly without `subPath`;
`bundle.yaml` at the same root records its compatibility and provenance.

The checked-in `tool-contract.json` records the stable `workload-diagnostics`
intent and each helper's allowed operation. `debug-report --json` emits a
deterministic JSON summary with `status: ready|not-ready`, containing only
check identities and success statuses for one-time or post-upgrade readiness.
Use `debug-tls --ca FILE` when the endpoint must be verified against
a supplied local CA, and `debug-dns --server HOST#PORT` for a non-default
resolver port.

Run the upstream proof with `make -C utils/workload-debug integration-test`.
It builds the image and exercises all helpers in a disposable fixture setup,
including a kind service account/token, under the same non-root,
read-only/no-capabilities policy used in deployment. The test is intentionally
not skippable when Docker, kind, or kubectl is unavailable.

## Incident checklist

1. Confirm the image digest and signature before starting the session.
2. Start with `report` and a DNS check; record output in the incident ticket.
3. Use `tls` to check certificate negotiation and `http` for the endpoint.
4. Use `kube-api` only for the minimum read-only path required by the incident.
5. Never put bearer tokens, cookies, or private keys in command arguments or
   captured output. Terminate and clean up the DebugSession when done.

The helpers return the underlying network command's status. `debug-report`
always emits a report and exposes the number of failed optional checks as
`checks_failed` so an unreachable target does not hide the rest of the report.
