# syntax=docker/dockerfile:1.7
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27@sha256:c5b07c17f54c5f22230c4b4da6e90249165cf55368e01a52808cb92064e18836 AS uploader-builder
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY uploader/main.go .
RUN GO111MODULE=off CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags='-s -w' -o /out/diagnostic-artifact-upload .
COPY copier/main.go /src/diagnostic-artifact-safe-copy.go
RUN GO111MODULE=off CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags='-s -w' -o /out/diagnostic-artifact-safe-copy /src/diagnostic-artifact-safe-copy.go

FROM busybox:1.37@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0

LABEL org.opencontainers.image.title="Diagnostic artifact collector" \
      org.opencontainers.image.description="Immutable bounded diagnostic recipes with archive handoff" \
      org.opencontainers.image.licenses="Apache-2.0 AND GPL-2.0-only" \
      org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/tree/main/utils/images/diagnostic-artifact-collector"

RUN install -d -o 65532 -g 65532 /output /host-coredumps /etc/ssl/certs && \
    install -d -o 0 -g 0 -m 0555 \
      /usr/share/breakglass/runbooks/upstream/diagnostic-artifact-collection \
      /usr/share/breakglass/runbooks/internal

# BusyBox is intentionally kept as the tiny runtime base. Copy the pinned
# builder's CA bundle so the uploader verifies HTTPS peers instead of silently
# falling back to an empty trust store.
COPY --from=uploader-builder --chmod=0644 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --chmod=0755 bin/diagnostic-artifact-collector /usr/local/bin/diagnostic-artifact-collector
COPY --from=uploader-builder --chmod=0755 /out/diagnostic-artifact-upload /usr/local/bin/diagnostic-artifact-upload
COPY --from=uploader-builder --chmod=0755 /out/diagnostic-artifact-safe-copy /usr/local/bin/diagnostic-artifact-safe-copy
COPY --chmod=0644 motd README.md RUNBOOK.md /usr/share/breakglass/runbooks/upstream/diagnostic-artifact-collection/
COPY --chmod=0644 motd /etc/motd

USER 65532:65532
WORKDIR /output

ENTRYPOINT ["/usr/local/bin/diagnostic-artifact-collector"]
CMD ["--help"]
