# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Build natively and cross-compile: running the Go toolchain under QEMU for
# foreign targets takes long enough to exhaust CI job timeouts.
FROM --platform=$BUILDPLATFORM golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d AS kubestr-builder

ARG TARGETARCH

ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} GOPROXY=https://proxy.golang.org
# kubestr and its Go module graph come from kubestr/go.mod and kubestr/go.sum,
# which Dependabot tracks; go.sum authenticates every downloaded module,
# including kubestr itself. The build fails if go.sum lacks an entry or if
# kubestr's own replace directives are not mirrored in kubestr/go.mod. The
# patched source replaces only the kubestr module, so the binary links exactly
# the tracked graph (checked below) and dependency bumps (for example
# golang.org/x/net) need no Dockerfile edits.
# kubestr creates the fio Pod without a security context, registry credentials
# or an owner. The patch runs it as the image user with fsGroup, passes the
# runner's pull secrets and makes the runner Pod own every generated object.
COPY kubestr/go.mod kubestr/go.sum /src/tools/
COPY patches/kubestr-fio-breakglass-pod-contract.patch /src/patches/
WORKDIR /src/tools
RUN set -eux; \
    cp go.sum /tmp/tracked-go.sum; \
    go mod download github.com/kastenhq/kubestr; \
    go list -m -f '{{.Path}} {{.Version}}' all > /tmp/tracked-modules; \
    mkdir -p /src/kubestr /out; \
    cp -a "$(go list -m -f '{{.Dir}}' github.com/kastenhq/kubestr)/." /src/kubestr/; \
    chmod -R u+w /src/kubestr; \
    sed -n 's/^replace //; s/^[[:space:]]*//; /=>/p' /src/kubestr/go.mod > /tmp/upstream-replaces; \
    sed -n 's/^replace //; s/^[[:space:]]*//; /=>/p' go.mod > /tmp/tracked-replaces; \
    cmp /tmp/upstream-replaces /tmp/tracked-replaces || { echo "kubestr replace directives differ from kubestr/go.mod" >&2; exit 1; }; \
    git -C /src/kubestr apply --verbose /src/patches/kubestr-fio-breakglass-pod-contract.patch; \
    go mod edit -replace github.com/kastenhq/kubestr=/src/kubestr; \
    GOARCH="$(go env GOHOSTARCH)" go test github.com/kastenhq/kubestr/pkg/fio; \
    go build -trimpath -ldflags='-s -w' -o /out/kubestr github.com/kastenhq/kubestr; \
    cmp go.sum /tmp/tracked-go.sum || { echo "kubestr/go.sum is incomplete; run go mod tidy in utils/images/storage-debug/kubestr" >&2; exit 1; }; \
    go version -m /out/kubestr > /out/kubestr-build-info; \
    cat /out/kubestr-build-info; \
    awk 'NR == FNR { tracked[$1] = $2; next } ($1 == "dep" || $1 == "mod") && tracked[$2] != $3 { print "linked " $2 " " $3 " differs from kubestr/go.mod"; bad = 1 } END { exit bad }' \
        /tmp/tracked-modules /out/kubestr-build-info

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="Storage diagnostics utilities" \
      org.opencontainers.image.description="Bounded mounted-volume, performance, CSI snapshot/restore, and block-volume diagnostics" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/tree/main/utils/images/storage-debug" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="alpine:3.24" \
      org.opencontainers.image.base.digest="sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf" \
      io.telekom.breakglass.intent="storage-diagnostics" \
      io.telekom.breakglass.image.role="debug-storage"

# Package versions follow the digest-pinned Alpine 3.24 base (Dependabot
# docker): the inherited set is upgraded from the matching release repository
# so security fixes land on rebuild, and the versions actually installed are
# recorded in the image and its SBOM instead of being pinned here.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache \
    && apk add --no-cache fio ioping \
    && install -d /usr/share/breakglass \
    && apk list --installed --no-network > /usr/share/breakglass/installed-packages 2>/dev/null \
    && grep -q "^fio-" /usr/share/breakglass/installed-packages \
    && chmod 0444 /usr/share/breakglass/installed-packages \
    && addgroup -S -g 65532 debug \
    && adduser -S -D -H -u 65532 -G debug debug \
    && install -d -o debug -g debug /scratch /reports /usr/share/storage-debug \
    && install -d -o root -g root /usr/share/breakglass/runbooks/upstream/storage-diagnostics

COPY --from=kubestr-builder /out/kubestr /usr/libexec/storage-debug/kubestr
COPY --from=kubestr-builder /out/kubestr-build-info /usr/share/breakglass/kubestr-build-info
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
