# SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

FROM node:23-alpine AS npm_builder
WORKDIR /workspace
COPY ./frontend /
RUN npm i
RUN npm run build

# Build the manager binary
FROM golang:1.24.9 AS builder
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

FROM gcr.io/distroless/static:nonroot
WORKDIR /

COPY --from=builder /workspace/breakglass .
COPY --from=npm_builder  /dist /frontend/dist

USER 65532
ENTRYPOINT [ "/breakglass" ]
