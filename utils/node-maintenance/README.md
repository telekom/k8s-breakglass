<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Kubernetes node-maintenance image

This is a generic, standalone image for a narrowly scoped node-network
incident workflow. It is multi-architecture (`linux/amd64` and `linux/arm64`)
and starts from the digest-pinned Alpine base in [`Dockerfile`](Dockerfile).

The image exposes exactly two supported commands:

* `node-recovery` collects read-only link, address, route, neighbor,
  NIC, resolver, and kernel evidence.
* `network-repair` performs exactly one of `link-cycle`, `flush-neighbors`, or
  `restart-autonegotiation`.

There is no supported unrestricted shell, package manager, compiler, packet
capture tool, port scanner, or general-purpose network toolbox. The entrypoint
dispatches only the two fixed command names. The image must run as root with a
privileged, host-networked pod for repairs; preflight is read-only but still
requires the same explicit target and confirmation gates.

## Guardrails

Every helper requires `--target-node NODE`, `--interface IFACE`,
`--evidence-dir ABSOLUTE_PATH`, and the command-specific confirmation token.
No default interface or node is inferred. The target must also exactly match
the local host identity returned by `hostname`; a target name is never treated
as merely descriptive. Targets accept only shell-safe identifiers, and repair
actions are validated against a fixed allowlist before any mutation. Evidence
must be a dedicated evidence mount or child directory (for example
`/evidence/run-123`), may
not be a system root, and may not resolve through a symlink. Evidence includes
command exit statuses and metadata and is produced before and after a repair
even when the action fails.

## Invocation

Use the runbooks in [`runbooks/`](runbooks/) and substitute every placeholder:

```text
node-recovery \
  --target-node NODE_NAME \
  --interface IFACE_NAME \
  --evidence-dir /evidence \
  --confirm NODE-RECOVERY-PREFLIGHT

network-repair \
  --target-node NODE_NAME \
  --interface IFACE_NAME \
  --action ACTION \
  --evidence-dir /evidence \
  --confirm NETWORK-REPAIR
```

Do not add `sh`, `bash`, or arbitrary commands to a pod specification. If the
allowlisted helpers cannot diagnose an incident, stop and use the platform's
normal, separately approved host-debug process.

## Pod security boundary

Use host networking and the smallest required capability. The preflight is
read-only; repairs require `NET_ADMIN`, not blanket privileged mode. Mount a
dedicated empty directory at `/evidence` and do not mount `/`, `/etc`, `/proc`,
`/sys`, or another host-system path. A representative security context is:

```yaml
hostNetwork: true
securityContext:
  runAsUser: 0
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
    add: [NET_ADMIN]
  seccompProfile:
    type: RuntimeDefault
```

The command dispatcher is the only supported entrypoint. The Alpine runtime
contains `/bin/sh` because the fixed helpers are POSIX scripts, but invoking a
shell or any other binary by overriding the entrypoint is outside the support
and incident-audit boundary.

## Build, SBOM, and signing

Run `make test` for helper tests. `make build` creates a local image;
`make build-multiarch` uses BuildKit for both supported platforms and requests
in-toto provenance plus an SPDX SBOM (`--provenance=true --sbom=true`), writing
a local OCI archive (`node-maintenance.oci.tar` by default).
Release automation must resolve and retain the immutable registry digest, then
run `make sign DIGEST=...` and `make sbom DIGEST=... SBOM=...`. The Makefile
refuses signing or attestation without a digest, so a mutable tag is never the
signing subject. Package versions and the base manifest are in [`deps.lock`](deps.lock).
