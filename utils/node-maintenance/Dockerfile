# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# The manifest digest is pinned so every architecture starts from the same
# reviewed Alpine release. BuildKit resolves the selected architecture.
FROM alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

# Keep the runtime deliberately small. Do not add a general-purpose network
# toolbox, a compiler, a package manager, or an interactive shell entrypoint.
RUN apk add --no-cache \
        ethtool=6.14.1-r0 \
        iproute2-minimal=6.15.0-r0 \
    && rm -f /sbin/apk /sbin/apk.static

COPY bin/node-maintenance /usr/local/bin/node-maintenance
COPY lib/common.sh /usr/local/libexec/node-maintenance/common.sh
COPY lib/network-repair.sh /usr/local/libexec/node-maintenance/network-repair
COPY lib/node-recovery-preflight.sh /usr/local/libexec/node-maintenance/node-recovery
COPY MOTD /etc/motd
COPY README.md /usr/share/node-maintenance/README.md
COPY runbooks/network-repair.md /usr/share/node-maintenance/runbooks/network-repair.md
COPY runbooks/node-recovery-preflight.md /usr/share/node-maintenance/runbooks/node-recovery-preflight.md

RUN chmod 0555 /usr/local/bin/node-maintenance \
        /usr/local/libexec/node-maintenance/network-repair \
        /usr/local/libexec/node-maintenance/node-recovery \
    && chmod 0444 /usr/local/libexec/node-maintenance/common.sh /etc/motd \
        /usr/share/node-maintenance/README.md \
        /usr/share/node-maintenance/runbooks/network-repair.md \
        /usr/share/node-maintenance/runbooks/node-recovery-preflight.md \
    && mkdir -p /evidence /runbooks/internal \
    && chmod 0700 /evidence \
    && chmod 0755 /runbooks /runbooks/internal

LABEL org.opencontainers.image.title="Kubernetes node maintenance" \
      org.opencontainers.image.description="Allowlisted, evidence-producing node network repair and recovery preflight helpers" \
      org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/blob/main/docs/node-maintenance.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Deutsche Telekom" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1" \
      io.telekom.breakglass.node-maintenance.commands="node-recovery,network-repair" \
      io.telekom.breakglass.node-maintenance.shell="not-supported" \
      io.telekom.breakglass.node-maintenance.capabilities="NET_ADMIN"

# The image is root only for the explicitly allowlisted host-network operation.
# Controller-owned immutable templates must use a no-capabilities preflight
# context and a separate NET_ADMIN-only repair context; privileged is not part
# of this image contract. The dispatcher rejects every other helper name.
USER 0
ENTRYPOINT ["/usr/local/bin/node-maintenance"]
