# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# Package versions follow the digest-pinned base; upgrade the inherited set so
# Alpine security fixes land on rebuild.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache \
    && apk add --no-cache \
    tmux \
    bash \
    curl \
    bind-tools \
    netcat-openbsd \
    iproute2 \
    procps \
    && rm -rf /var/cache/apk/*

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["sleep infinity"]
