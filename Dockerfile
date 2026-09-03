FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3 AS npm_builder
WORKDIR /workspace
ARG UI_FLAVOUR=oss
ENV VITE_UI_FLAVOUR=$UI_FLAVOUR
LABEL org.breakglass.ui.flavour.default="oss"
COPY ./frontend /workspace/frontend
RUN set -eux; cd /workspace/frontend; \
	npm ci --no-audit --no-fund; \
	npm run build

# Build the manager binary
FROM golang:1.27@sha256:512690a5660563b57d37ecc31129e7f136e831db2aed24a1dbeb8ad7380dc0fa AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/ cmd/
COPY api/ api/
COPY pkg/ pkg/

# Build
# When TARGETARCH is set (e.g., via BuildKit/buildx --platform), it is forwarded to GOARCH
# for cross-compilation. When unset (classic docker build), GOARCH falls back to the Go
# toolchain's host architecture via $(go env GOARCH).
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-$(go env GOARCH)} go build -a -trimpath \
    -ldflags "-s -w -X github.com/telekom/k8s-breakglass/pkg/version.Version=${VERSION} \
              -X github.com/telekom/k8s-breakglass/pkg/version.GitCommit=${GIT_COMMIT} \
              -X github.com/telekom/k8s-breakglass/pkg/version.BuildDate=${BUILD_DATE}" \
    -o breakglass ./cmd

FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
WORKDIR /

COPY --from=builder /workspace/breakglass .
COPY --from=npm_builder /workspace/frontend/dist /frontend/dist
COPY --from=builder /etc/ssl/certs/ /etc/ssl/certs/

# Copy license files for compliance
COPY LICENSES /licenses/
COPY LICENSE /licenses/PROJECT_LICENSE

# OCI Image Labels - Standard metadata for container images
LABEL org.opencontainers.image.title="Kubernetes Breakglass"
LABEL org.opencontainers.image.description="Secure, auditable privilege escalation system for Kubernetes clusters with real-time webhook integration"
LABEL org.opencontainers.image.url="https://github.com/telekom/k8s-breakglass"
LABEL org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/tree/main/docs"
LABEL org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="Deutsche Telekom"

USER 65532
ENTRYPOINT [ "/breakglass" ]
