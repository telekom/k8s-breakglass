# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27@sha256:c5b07c17f54c5f22230c4b4da6e90249165cf55368e01a52808cb92064e18836 AS kubestr-builder

ARG TARGETARCH
ARG KUBESTR_VERSION=v0.4.49
ARG KUBESTR_COMMIT=01940ed37be9a0c7a70d80cd26c648eaa11e5174

ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} GOPROXY=https://proxy.golang.org
RUN git clone --depth=1 --branch "${KUBESTR_VERSION}" https://github.com/kastenhq/kubestr.git /src/kubestr \
    && test "$(git -C /src/kubestr rev-parse HEAD)" = "${KUBESTR_COMMIT}" \
    && go -C /src/kubestr get \
        github.com/moby/spdystream@v0.5.1 \
        golang.org/x/crypto@v0.53.0 \
        golang.org/x/net@v0.56.0 \
        golang.org/x/oauth2@v0.27.0 \
        golang.org/x/text@v0.39.0 \
    && go -C /src/kubestr mod tidy \
    && go -C /src/kubestr build -mod=mod -trimpath -ldflags='-s -w' -o /out/kubestr . \
    && test -x /out/kubestr

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG FIO_VERSION=3.41-r0
ARG IOPING_VERSION=1.3-r0
ARG KUBESTR_VERSION=v0.4.49

LABEL org.opencontainers.image.title="Storage diagnostics utilities" \
      org.opencontainers.image.description="Bounded mounted-volume, performance, CSI snapshot/restore, and block-volume diagnostics" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/tree/main/utils/images/storage-debug" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="alpine:3.24" \
      org.opencontainers.image.base.digest="sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b" \
      io.telekom.breakglass.intent="storage-diagnostics" \
      io.telekom.breakglass.image.role="debug-storage"

# Install only the exact fio and ioping versions required by the utility
# contract. Do not upgrade the inherited package set: the base digest and
# exact package selections must remain reproducible as one Alpine release.
RUN apk add --no-cache \
      "fio=${FIO_VERSION}" \
      "ioping=${IOPING_VERSION}" \
    && addgroup -S -g 65532 debug \
    && adduser -S -D -H -u 65532 -G debug debug \
    && install -d -o debug -g debug /scratch /reports /usr/share/storage-debug \
    && install -d -o root -g root /usr/share/breakglass/runbooks/upstream/storage-diagnostics

COPY --from=kubestr-builder /out/kubestr /usr/libexec/storage-debug/kubestr
COPY --chmod=0755 bin/storage-report bin/storage-diagnostics /usr/local/bin/
COPY --chmod=0644 motd /etc/motd
COPY --chmod=0644 README.md RUNBOOK.md /usr/share/breakglass/runbooks/upstream/storage-diagnostics/
COPY --chmod=0644 versions.env /usr/share/storage-debug/versions.env
COPY --chmod=0644 LICENSES/THIRD_PARTY.md /licenses/THIRD_PARTY.md

USER 65532:65532
WORKDIR /scratch

ENV STORAGE_TEST_PATH=/scratch \
    STORAGE_REPORT_DIR=/reports \
    STORAGE_TEST_SIZE_MB=16 \
    STORAGE_TEST_RUNTIME_SECONDS=5 \
    STORAGE_IOPING_COUNT=5

ENTRYPOINT ["/usr/local/bin/storage-diagnostics"]
CMD ["help"]
