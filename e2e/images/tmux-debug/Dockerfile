# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.20@sha256:765942a4039992336de8dd5db680586e1a206607dd06170ff0a37267a9e01958

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
