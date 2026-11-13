# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

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
