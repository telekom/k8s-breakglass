FROM node:25-alpine@sha256:b9b5737eabd423ba73b21fe2e82332c0656d571daf1ebf19b0f89d0dd0d3ca93 AS npm_builder
WORKDIR /workspace
ARG UI_FLAVOUR=oss
ENV VITE_UI_FLAVOUR=$UI_FLAVOUR
LABEL org.breakglass.ui.flavour.default="oss"
COPY ./frontend /workspace/frontend
RUN set -eux; cd /workspace/frontend; \
	npm ci --no-audit --no-fund; \
	npm run build

# Build the manager binary
FROM golang:1.25.7@sha256:cc737435e2742bd6da3b7d575623968683609a3d2e0695f9d85bee84071c08e6 AS builder
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
COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY pkg/ pkg/
# COPY internal/ internal/

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
    -o breakglass cmd/main.go

FROM gcr.io/distroless/static:nonroot@sha256:f9f84bd968430d7d35e8e6d55c40efb0b980829ec42920a49e60e65eac0d83fc
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
