# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27@sha256:4013ae0f9e7994f8535c58c811f8f863fbed38b72e0d51e6592156f758d66146 AS network-action-builder

ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY cmd/network-action/ ./
RUN CGO_ENABLED=0 GO111MODULE=off GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-$(go env GOARCH)} \
      go build -trimpath -ldflags='-s -w' -o /out/network-action .

# The manifest digest is pinned so every architecture starts from the same
# reviewed Alpine release. BuildKit resolves the selected architecture.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

# Keep the runtime deliberately small. Do not add a general-purpose network
# toolbox, a compiler, a package manager, or an interactive shell entrypoint.
RUN apk add --no-cache \
        ethtool=7.0-r0 \
        flock=2.42.1-r0 \
        iproute2=7.0.0-r0 \
        libcrypto3=3.5.8-r0 \
        libssl3=3.5.8-r0 \
    && rm -f /sbin/apk /sbin/apk.static

COPY bin/node-maintenance /usr/local/bin/node-maintenance
COPY --from=network-action-builder /out/network-action /usr/local/sbin/network-action
COPY lib/common.sh /usr/local/libexec/node-maintenance/common.sh
COPY lib/network-repair.sh /usr/local/libexec/node-maintenance/network-repair
COPY lib/node-recovery-preflight.sh /usr/local/libexec/node-maintenance/node-recovery
COPY lib/kexec-recovery-validate.sh /usr/local/libexec/node-maintenance/kexec-recovery-validate
COPY MOTD /etc/motd
COPY README.md /usr/share/breakglass/runbooks/upstream/node-maintenance/README.md
COPY runbooks/network-repair.md /usr/share/breakglass/runbooks/upstream/node-maintenance/network-repair.md
COPY runbooks/node-recovery-preflight.md /usr/share/breakglass/runbooks/upstream/node-maintenance/node-recovery-preflight.md
COPY runbooks/kexec-recovery-validation.md /usr/share/breakglass/runbooks/upstream/node-maintenance/kexec-recovery-validation.md

RUN chmod 0555 /usr/local/bin/node-maintenance \
        /usr/local/sbin/network-action \
        /usr/local/libexec/node-maintenance/network-repair \
        /usr/local/libexec/node-maintenance/node-recovery \
        /usr/local/libexec/node-maintenance/kexec-recovery-validate \
    && chmod 0444 /usr/local/libexec/node-maintenance/common.sh /etc/motd \
        /usr/share/breakglass/runbooks/upstream/node-maintenance/README.md \
        /usr/share/breakglass/runbooks/upstream/node-maintenance/network-repair.md \
        /usr/share/breakglass/runbooks/upstream/node-maintenance/node-recovery-preflight.md \
        /usr/share/breakglass/runbooks/upstream/node-maintenance/kexec-recovery-validation.md \
    && mkdir -p /evidence /usr/share/breakglass/runbooks/internal \
    && chmod 0700 /evidence \
    && chmod 0755 /usr/share/breakglass/runbooks/internal

LABEL org.opencontainers.image.title="Kubernetes node maintenance" \
      org.opencontainers.image.description="Allowlisted, evidence-producing node network repair and recovery preflight helpers" \
      org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/blob/main/docs/node-maintenance.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Deutsche Telekom" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b" \
      io.telekom.breakglass.node-maintenance.commands="node-recovery,network-repair,kexec-recovery-validate" \
      io.telekom.breakglass.node-maintenance.shell="not-supported" \
      io.telekom.breakglass.node-maintenance.capabilities="NET_ADMIN"

# The image is root only for the explicitly allowlisted host-network operation.
# Controller-owned immutable templates must use a no-capabilities preflight
# context, a separate NET_ADMIN-only repair context, and a no-capability kexec
# validation context. The image has no kexec executable or SYS_BOOT capability;
# privileged is not part of this contract. The dispatcher rejects every other
# helper name.
# hadolint ignore=DL3002
USER 0
ENTRYPOINT ["/usr/local/bin/node-maintenance"]
