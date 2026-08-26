# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG FIO_VERSION=3.41-r0
ARG IOPING_VERSION=1.3-r0

LABEL org.opencontainers.image.title="Storage debug utilities" \
      org.opencontainers.image.description="Bounded fio and ioping checks with deterministic reports" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/tree/main/utils/images/storage-debug"

# fio and ioping are deliberately version-pinned. Alpine's busybox provides the
# small POSIX utilities used by the scripts, so no floating package is pulled in.
RUN apk add --no-cache \
      "fio=${FIO_VERSION}" \
      "ioping=${IOPING_VERSION}" \
    && addgroup -S -g 65532 debug \
    && adduser -S -D -H -u 65532 -G debug debug \
    && install -d -o debug -g debug /scratch /reports

COPY --chmod=0755 bin/storage-report /usr/local/bin/storage-report
COPY --chmod=0644 motd /etc/motd

USER 65532:65532
WORKDIR /scratch

ENV STORAGE_TEST_PATH=/scratch \
    STORAGE_REPORT_DIR=/reports \
    STORAGE_TEST_SIZE_MB=16 \
    STORAGE_TEST_RUNTIME_SECONDS=5 \
    STORAGE_IOPING_COUNT=5

ENTRYPOINT ["/usr/local/bin/storage-report"]
CMD ["--help"]
