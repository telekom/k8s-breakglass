# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG VERSION=0.1.0
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG REVISION=${VCS_REF}
ARG CREATED=${BUILD_DATE}

# The Alpine 3.24 release and its base manifest are pinned. Refresh deps.lock
# and the SBOM together whenever this is updated.
# hadolint ignore=DL3018
RUN apk add --no-cache \
      bash=5.3.9-r1 \
      bind-tools=9.20.26-r0 \
      ca-certificates=20260611-r0 \
      curl=8.21.0-r0 \
      jq=1.8.1-r0 \
      openssl=3.5.7-r0 \
      tini=0.19.0-r3 \
    && addgroup -S -g 65532 debug \
    && adduser -S -D -H -u 65532 -G debug debug \
    && mkdir -p /home/debug /usr/local/share/workload-debug \
    && chown 65532:65532 /home/debug \
    && update-ca-certificates

COPY scripts/ /usr/local/bin/
COPY MOTD /usr/local/share/workload-debug/MOTD
COPY README.md RUNBOOK.md /usr/local/share/workload-debug/
COPY MOTD /etc/motd
COPY LICENSE /licenses/PROJECT_LICENSE
COPY LICENSES/ /licenses/

RUN chmod 0555 /usr/local/bin/debug-* /usr/local/bin/workload-debug \
      /usr/local/bin/workload-debug-entrypoint \
    && chmod 0444 /usr/local/share/workload-debug/MOTD \
      /usr/local/share/workload-debug/README.md \
      /usr/local/share/workload-debug/RUNBOOK.md /etc/motd \
    && printf '%s\n' \
      "export PATH=\"/usr/local/bin:\$PATH\"" \
      'if [ -t 1 ] && [ -r /usr/local/share/workload-debug/MOTD ]; then cat /usr/local/share/workload-debug/MOTD; fi' \
      > /etc/profile.d/workload-debug.sh \
    && chmod 0444 /etc/profile.d/workload-debug.sh

LABEL org.opencontainers.image.title="Breakglass workload-debug" \
      org.opencontainers.image.description="Restricted, generic Kubernetes workload diagnostics image" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.url="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/blob/main/docs/runbooks/workload-debug.md" \
      org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass/tree/main/utils/workload-debug" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Deutsche Telekom AG" \
      org.opencontainers.image.base.name="alpine:3.24" \
      org.opencontainers.image.base.digest="sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b" \
      io.telekom.breakglass.image.role="debug-workload" \
      io.telekom.breakglass.sbom.format="spdx-json" \
      io.telekom.breakglass.signing="cosign-keyless"

ENV HOME=/home/debug \
    PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

WORKDIR /
USER 65532:65532
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/workload-debug-entrypoint"]
CMD ["/bin/sh"]
