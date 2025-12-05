FROM node:25-alpine@sha256:fd164609b5ab0c6d49bac138ae06c347e72261ec6ae1de32b6aa9f5ee2271110 AS npm_builder
WORKDIR /workspace
ARG UI_FLAVOUR=oss
ENV VITE_UI_FLAVOUR=$UI_FLAVOUR
LABEL org.breakglass.ui.flavour.default="oss"
COPY ./frontend /workspace/frontend
RUN set -eux; cd /workspace/frontend; \
	npm ci --no-audit --no-fund; \
	npm run build

# Build the manager binary
FROM golang:1.25.5@sha256:20b91eda7a9627c127c0225b0d4e8ec927b476fa4130c6760928b849d769c149 AS builder
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
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 go build -a -o breakglass cmd/main.go

FROM gcr.io/distroless/static:nonroot@sha256:2b7c93f6d6648c11f0e80a48558c8f77885eb0445213b8e69a6a0d7c89fc6ae4
WORKDIR /

COPY --from=builder /workspace/breakglass .
COPY --from=npm_builder /workspace/frontend/dist /frontend/dist
COPY --from=builder /etc/ssl/certs/ /etc/ssl/certs/

# Copy license files for compliance
COPY LICENSES /licenses/
COPY LICENCE /licenses/PROJECT_LICENCE

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
