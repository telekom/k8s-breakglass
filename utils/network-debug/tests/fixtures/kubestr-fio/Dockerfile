# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache fio=3.41-r0

# kubestr mounts a fresh PVC without an fsGroup override. This disposable
# fixture must be able to write the volume so fio performs a real test.
# hadolint ignore=DL3002
USER 0
