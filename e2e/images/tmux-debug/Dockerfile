# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache \
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
