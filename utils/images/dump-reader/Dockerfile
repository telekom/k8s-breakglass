# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

FROM busybox:1.37@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0

LABEL org.opencontainers.image.title="Dump reader utilities" \
      org.opencontainers.image.description="Read-only existing-file inspection, checksums, and copy-out" \
      org.opencontainers.image.licenses="Apache-2.0 AND GPL-2.0-only" \
      org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass" \
      org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/tree/main/utils/images/dump-reader"

# No dump-generation or debugger package is installed. BusyBox supplies the
# small POSIX utility set used by the helper; the pinned base is the only
# runtime dependency and no package manager is added. Numeric ownership keeps
# the image independent of mutable passwd/group databases.
RUN install -d -o 65532 -g 65532 /input /output /usr/share/dump-reader

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
