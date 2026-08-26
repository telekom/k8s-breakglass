# syntax=docker/dockerfile:1.7
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Build from the repository root:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f utils/cluster-validator/Dockerfile .
FROM golang:1.27@sha256:c5b07c17f54c5f22230c4b4da6e90249165cf55368e01a52808cb92064e18836 AS builder
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/cluster-validator ./cmd/cluster-validator
COPY pkg/clustervalidator ./pkg/clustervalidator
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH:-amd64} go build -a -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.gitCommit=${GIT_COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/cluster-validator ./cmd/cluster-validator

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

COPY --from=builder /out/cluster-validator /cluster-validator
COPY LICENSE /licenses/PROJECT_LICENSE
COPY LICENSES /licenses/
COPY utils/cluster-validator/MOTD /etc/motd
COPY utils/cluster-validator/README.md /usr/share/cluster-validator/README.md
COPY utils/cluster-validator/RUNBOOK.md /usr/share/cluster-validator/RUNBOOK.md

LABEL org.opencontainers.image.title="Kubernetes Cluster Validator" \
      org.opencontainers.image.description="Provider-neutral, read-only Kubernetes readiness reports for one-time and post-upgrade validation" \
      org.opencontainers.image.url="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/tree/main/utils/cluster-validator" \
      org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Deutsche Telekom" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$GIT_COMMIT \
      org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot" \
      com.deutschetelekom.cluster-validator.report-api-version="cluster-validator.telekom.com/v1alpha1" \
      com.deutschetelekom.cluster-validator.sbom="spdx-json" \
      com.deutschetelekom.cluster-validator.signing="sigstore-keyless"

USER 65532:65532
ENTRYPOINT ["/cluster-validator"]
