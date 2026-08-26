# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

LABEL org.opencontainers.image.title="Dump reader utilities" \
      org.opencontainers.image.description="Read-only existing-file inspection, checksums, and copy-out" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/tree/main/utils/images/dump-reader"

# No dump-generation or debugger package is installed. Alpine's busybox
# supplies stat, sha256sum, and cp; the pinned base is the only dependency.
RUN addgroup -S -g 65532 reader \
    && adduser -S -D -H -u 65532 -G reader reader \
    && install -d -o reader -g reader /input /output /usr/share/dump-reader

COPY --chmod=0755 bin/dump-reader /usr/local/bin/dump-reader
COPY --chmod=0644 motd /etc/motd
COPY --chmod=0644 README.md RUNBOOK.md /usr/share/dump-reader/

USER 65532:65532
WORKDIR /input

ENV DUMP_INPUT_DIR=/input \
    DUMP_OUTPUT_DIR=/output \
    DUMP_MAX_COPY_BYTES=1073741824

ENTRYPOINT ["/usr/local/bin/dump-reader"]
CMD ["help"]
