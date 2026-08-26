# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Alpine publishes this digest as a multi-platform image. Keep the digest and
# the release tag together: changing either requires a deliberate image review.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS runtime

ARG VERSION=0.1.0
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

# kubestr and pwru are built from immutable release tags in the tool stage.
# Building from source avoids downloading architecture-specific binaries at
# runtime and keeps both amd64 and arm64 in the same manifest list.
FROM golang:1.27@sha256:c5b07c17f54c5f22230c4b4da6e90249165cf55368e01a52808cb92064e18836 AS tools
ARG TARGETARCH
ARG KUBESTR_VERSION=v0.4.49
ARG KUBESTR_COMMIT=01940ed37be9a0c7a70d80cd26c648eaa11e5174
ARG PWRU_VERSION=v1.0.12
ARG PWRU_SHA256_AMD64=1ccaea22d97c283b09d2e2f0329789727c4f1b19aa99723e32b2e12d3a5e6dba
ARG PWRU_SHA256_ARM64=997516721a58b4f8ffe3504994cada472c9bcd78f1e819862bf61f1081684378

ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} GOPROXY=https://proxy.golang.org
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eux; \
	apt-get update; \
	apt-get install --no-install-recommends --yes ca-certificates=20250419 curl=8.14.1-2+deb13u4; \
	git clone --depth=1 --branch "${KUBESTR_VERSION}" https://github.com/kastenhq/kubestr.git /tmp/kubestr; \
	test "$(git -C /tmp/kubestr rev-parse HEAD)" = "${KUBESTR_COMMIT}"; \
	go -C /tmp/kubestr build -trimpath -ldflags='-s -w' -o /go/bin/kubestr .; \
	curl --fail --silent --show-error --location \
		"https://github.com/cilium/pwru/releases/download/${PWRU_VERSION}/pwru-linux-${TARGETARCH:-amd64}.tar.gz" \
		--output "/tmp/pwru-linux-${TARGETARCH:-amd64}.tar.gz"; \
	curl --fail --silent --show-error --location \
		"https://github.com/cilium/pwru/releases/download/${PWRU_VERSION}/pwru-linux-${TARGETARCH:-amd64}.tar.gz.sha256sum" \
		--output /tmp/pwru.sha256sum; \
	sed -i 's#^[0-9a-fA-F]*[[:space:]]\+#&/tmp/#' /tmp/pwru.sha256sum; \
	sha256sum -c /tmp/pwru.sha256sum; \
	case "${TARGETARCH:-amd64}" in \
		amd64) expected="${PWRU_SHA256_AMD64}" ;; \
		arm64) expected="${PWRU_SHA256_ARM64}" ;; \
		*) echo "unsupported target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
	esac; \
	test "$(sha256sum "/tmp/pwru-linux-${TARGETARCH:-amd64}.tar.gz" | cut -d' ' -f1)" = "${expected}"; \
	tar -xzf "/tmp/pwru-linux-${TARGETARCH:-amd64}.tar.gz" -C /go/bin; \
	apt-get purge --auto-remove --yes ca-certificates curl; \
	rm -rf /var/lib/apt/lists/* /tmp/kubestr "/tmp/pwru-linux-${TARGETARCH:-amd64}.tar.gz" /tmp/pwru.sha256sum; \
	test -x /go/bin/kubestr; \
	test -x /go/bin/pwru

FROM runtime

ARG VERSION=0.1.0
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG KUBESTR_VERSION=v0.4.49
ARG PWRU_VERSION=v1.0.12

LABEL org.opencontainers.image.title="Network Debug Utility" \
	org.opencontainers.image.description="Standalone, multi-architecture Kubernetes network troubleshooting toolbox" \
	org.opencontainers.image.url="https://github.com/telekom/k8s-breakglass" \
	org.opencontainers.image.documentation="https://github.com/telekom/k8s-breakglass/tree/main/utils/network-debug" \
	org.opencontainers.image.source="https://github.com/telekom/k8s-breakglass" \
	org.opencontainers.image.licenses="Apache-2.0" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${VCS_REF}" \
	org.opencontainers.image.created="${BUILD_DATE}" \
	org.opencontainers.image.base.name="docker.io/library/alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b" \
	org.opencontainers.image.base.digest="sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b" \
	org.opencontainers.image.vendor="Deutsche Telekom AG" \
	io.telekom.breakglass.intent="network-diagnostics" \
	io.telekom.breakglass.image.role="debug-network" \
	io.telekom.breakglass.security.capabilities="NET_RAW,NET_ADMIN,BPF,PERFMON"

# Keep this list intentionally focused. APK resolves dependencies for the
# digest-pinned Alpine release; versions are recorded in versions.env and
# refreshed together with the base digest by the image maintainer.
RUN apk add --no-cache \
	bash=5.3.9-r1 \
	bind-tools=9.20.26-r0 \
	busybox-extras=1.37.0-r31 \
	ca-certificates=20260611-r0 \
	coreutils=9.11-r0 \
	curl=8.21.0-r0 \
	ethtool=7.0-r0 \
	iproute2=7.0.0-r0 \
	iputils=20250605-r2 \
	iputils-ping=20250605-r2 \
	iputils-tracepath=20250605-r2 \
	jq=1.8.1-r0 \
	mtr=0.96-r2 \
	ncurses-terminfo=6.6_p20260516-r0 \
	openssl=3.5.7-r0 \
	netcat-openbsd=1.234.1-r0 \
	procps=4.0.6-r0 \
	tcpdump=4.99.6-r1 \
	traceroute=2.1.6-r0 \
	&& update-ca-certificates \
	&& rm -rf /var/cache/apk/*

COPY --from=tools /go/bin/kubestr /usr/local/bin/kubestr
COPY --from=tools /go/bin/pwru /usr/local/bin/pwru
COPY scripts/net-debug /usr/local/bin/net-debug
COPY scripts/net-report /usr/local/bin/net-report
COPY scripts/network-debug-profile.sh /etc/profile.d/network-debug.sh
COPY MOTD /etc/motd
COPY LICENSES /licenses
COPY versions.env /usr/share/network-debug/versions.env
COPY README.md RUNBOOK.md /usr/share/network-debug/

RUN chmod 0755 /usr/local/bin/net-debug /usr/local/bin/net-report /etc/profile.d/network-debug.sh \
	&& chmod 0644 /etc/motd /usr/share/network-debug/versions.env \
		/usr/share/network-debug/README.md /usr/share/network-debug/RUNBOOK.md \
	&& printf '%s\n' "${VERSION}" > /usr/share/network-debug/version \
	&& chmod 0644 /usr/share/network-debug/version

ENV NETWORK_DEBUG_VERSION=${VERSION}
ENV NETWORK_DEBUG_INTENT=network-diagnostics
ENV PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /work
# tcpdump and pwru require root or equivalent Linux capabilities. Consumers
# should drop capabilities and isolate the network namespace per the runbook.
# hadolint ignore=DL3002
USER 0
ENTRYPOINT ["/usr/local/bin/net-debug"]
CMD ["shell"]
