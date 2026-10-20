# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c AS network-action-builder

ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY cmd/network-action/ ./
RUN CGO_ENABLED=0 GO111MODULE=off GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-$(go env GOARCH)} \
      go build -trimpath -ldflags='-s -w' -o /out/network-action .
WORKDIR /src-service-action
COPY cmd/service-action/ ./
RUN CGO_ENABLED=0 GO111MODULE=off GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-$(go env GOARCH)} \
      go build -trimpath -ldflags='-s -w' -o /out/service-action .

FROM golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c AS kexec-action-builder

ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY cmd/kexec-action/ ./
RUN CGO_ENABLED=0 GO111MODULE=off GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-$(go env GOARCH)} \
      go build -trimpath -ldflags='-s -w' -o /out/kexec-action .

# The manifest digest is pinned so every architecture starts from the same
# reviewed Alpine release. BuildKit resolves the selected architecture.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

# Keep the runtime deliberately small. Do not add a general-purpose network
# toolbox, a compiler, a package manager, or an interactive shell entrypoint.
RUN apk add --no-cache \
        ethtool=7.0-r0 \
        flock=2.42.3-r1 \
        iproute2=7.0.0-r0 \
        kmod=34.2-r1 \
        xz-libs=5.8.4-r0 \
        zlib=1.3.2-r0 \
        zstd-libs=1.5.7-r2 \
        libcrypto3=3.5.8-r0 \
        libssl3=3.5.8-r0 \
    && rm -f /sbin/apk /sbin/apk.static

COPY bin/node-maintenance /usr/local/bin/node-maintenance
COPY --from=network-action-builder /out/network-action /usr/local/sbin/network-action
COPY --from=network-action-builder /out/service-action /usr/local/sbin/service-action
COPY --from=kexec-action-builder /out/kexec-action /usr/local/sbin/kexec-action
COPY lib/common.sh /usr/local/libexec/node-maintenance/common.sh
COPY lib/network-repair.sh /usr/local/libexec/node-maintenance/network-repair
COPY lib/node-recovery-preflight.sh /usr/local/libexec/node-maintenance/node-recovery
COPY lib/kexec-recovery-validate.sh /usr/local/libexec/node-maintenance/kexec-recovery-validate
COPY lib/service-restart.sh /usr/local/libexec/node-maintenance/service-restart
COPY lib/module-load.sh /usr/local/libexec/node-maintenance/module-load
COPY lib/sriov-reprovision.sh /usr/local/libexec/node-maintenance/sriov-reprovision
COPY runbooks/sriov-reprovision.md /usr/share/breakglass/runbooks/upstream/node-maintenance/sriov-reprovision.md
COPY runbooks/module-load.md /usr/share/breakglass/runbooks/upstream/node-maintenance/module-load.md
COPY lib/kexec-recovery-validate.sh /usr/local/libexec/node-maintenance/kexec-recovery
COPY MOTD /etc/motd
COPY README.md /usr/share/breakglass/runbooks/upstream/node-maintenance/README.md
COPY runbooks/network-repair.md /usr/share/breakglass/runbooks/upstream/node-maintenance/network-repair.md
COPY runbooks/node-recovery-preflight.md /usr/share/breakglass/runbooks/upstream/node-maintenance/node-recovery-preflight.md
COPY runbooks/kexec-recovery-validation.md /usr/share/breakglass/runbooks/upstream/node-maintenance/kexec-recovery-validation.md
COPY runbooks/service-restart.md /usr/share/breakglass/runbooks/upstream/node-maintenance/service-restart.md

RUN chmod 0555 /usr/local/bin/node-maintenance \
        /usr/local/sbin/network-action \
        /usr/local/sbin/service-action \
        /usr/local/libexec/node-maintenance/service-restart \
        /usr/local/libexec/node-maintenance/module-load \
        /usr/local/libexec/node-maintenance/sriov-reprovision \
        /usr/local/sbin/kexec-action \
        /usr/local/libexec/node-maintenance/network-repair \
        /usr/local/libexec/node-maintenance/node-recovery \
        /usr/local/libexec/node-maintenance/kexec-recovery-validate \
        /usr/local/libexec/node-maintenance/kexec-recovery \
    && chmod 0444 /usr/local/libexec/node-maintenance/common.sh /etc/motd \
        /usr/share/breakglass/runbooks/upstream/node-maintenance/README.md \
        /usr/share/breakglass/runbooks/upstream/node-maintenance/network-repair.md \
        /usr/share/breakglass/runbooks/upstream/node-maintenance/node-recovery-preflight.md \
        /usr/share/breakglass/runbooks/upstream/node-maintenance/kexec-recovery-validation.md \
        /usr/share/breakglass/runbooks/upstream/node-maintenance/service-restart.md \
        /usr/share/breakglass/runbooks/upstream/node-maintenance/module-load.md \
        /usr/share/breakglass/runbooks/upstream/node-maintenance/sriov-reprovision.md \
    && mkdir -p /evidence /usr/share/breakglass/runbooks/internal /usr/share/breakglass/modprobe.d \
    && chmod 0700 /evidence \
    && chmod 0755 /usr/share/breakglass/runbooks/internal

LABEL org.opencontainers.image.title="Kubernetes node maintenance" \
      org.opencontainers.image.description="Allowlisted, evidence-producing node network repair, recovery preflight, and kexec recovery helpers" \
      org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/blob/main/docs/node-maintenance.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Deutsche Telekom" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6" \
      io.telekom.breakglass.node-maintenance.commands="node-recovery,network-repair,kexec-recovery-validate,kexec-recovery,service-restart,module-load,sriov-reprovision" \
      io.telekom.breakglass.node-maintenance.shell="not-supported" \
      io.telekom.breakglass.node-maintenance.capabilities="NET_ADMIN,SYS_BOOT,SYS_MODULE"

# The image is root only for the explicitly allowlisted host-network operation.
# Controller-owned immutable templates must use a no-capabilities preflight
# context, a separate NET_ADMIN-only repair context, a no-capability kexec
# validation context, and a separate SYS_BOOT-only kexec execution context.
# privileged is not part of this contract. The dispatcher rejects every other
# helper name.
# hadolint ignore=DL3002
USER 0
ENTRYPOINT ["/usr/local/bin/node-maintenance"]
