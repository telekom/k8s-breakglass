# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# netshoot v0.16 supplies the overlapping network troubleshooting tools. Keep
# the release tag and immutable multi-architecture manifest digest together.
# The upstream package set is inherited as a unit; only pwru and the
# contract/docs below are added here.
FROM ghcr.io/nicolaka/netshoot:v0.16@sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70 AS runtime

ARG VERSION=0.1.0
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

# pwru is fetched from an immutable release in the tool stage. The transient
# download packages come from the pinned builder's configured repositories and
# are removed before the checksum-verified binary is copied into runtime.
# Storage tooling is intentionally excluded; kubestr belongs to storage-debug.
FROM golang:1.27@sha256:c5b07c17f54c5f22230c4b4da6e90249165cf55368e01a52808cb92064e18836 AS tools
ARG TARGETARCH
ARG PWRU_VERSION=v1.0.12
ARG PWRU_SHA256_AMD64=1ccaea22d97c283b09d2e2f0329789727c4f1b19aa99723e32b2e12d3a5e6dba
ARG PWRU_SHA256_ARM64=997516721a58b4f8ffe3504994cada472c9bcd78f1e819862bf61f1081684378

ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} GOPROXY=https://proxy.golang.org
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# The build-only package revisions follow the builder's current repositories;
# pinning them would couple rebuilds to rotating APT snapshots.
# hadolint ignore=DL3008
RUN set -eux; \
	apt-get update; \
	apt-get install --no-install-recommends --yes ca-certificates curl; \
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
	rm -rf /var/lib/apt/lists/* "/tmp/pwru-linux-${TARGETARCH:-amd64}.tar.gz" /tmp/pwru.sha256sum; \
	test -x /go/bin/pwru

FROM runtime

ARG VERSION=0.1.0
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
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
	org.opencontainers.image.base.name="ghcr.io/nicolaka/netshoot:v0.16@sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70" \
	org.opencontainers.image.base.digest="sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70" \
	org.opencontainers.image.vendor="Deutsche Telekom AG" \
	io.telekom.breakglass.intent="network-diagnostics" \
	io.telekom.breakglass.image.role="debug-network" \
	io.telekom.breakglass.security.capabilities="NET_RAW,NET_ADMIN,BPF,PERFMON,SYS_RESOURCE,SYS_PTRACE"

COPY --from=tools /go/bin/pwru /usr/local/bin/pwru
COPY scripts/net-debug /usr/local/bin/net-debug
COPY scripts/net-report /usr/local/bin/net-report
COPY scripts/network-debug-profile.sh /etc/profile.d/network-debug.sh
COPY MOTD /etc/motd
COPY LICENSES /licenses
COPY versions.env /usr/share/breakglass/runbooks/upstream/network-debug/versions.env
COPY README.md RUNBOOK.md /usr/share/breakglass/runbooks/upstream/network-debug/

RUN chmod 0755 /usr/local/bin/net-debug /usr/local/bin/net-report /etc/profile.d/network-debug.sh \
	&& chmod 0644 /etc/motd /usr/share/breakglass/runbooks/upstream/network-debug/versions.env \
		/usr/share/breakglass/runbooks/upstream/network-debug/README.md /usr/share/breakglass/runbooks/upstream/network-debug/RUNBOOK.md \
	&& printf '%s\n' "${VERSION}" > /usr/share/breakglass/runbooks/upstream/network-debug/version \
	&& chmod 0644 /usr/share/breakglass/runbooks/upstream/network-debug/version \
	&& mkdir -p /usr/share/breakglass/runbooks/internal \
	&& chmod 0755 /usr/share /usr/share/breakglass /usr/share/breakglass/runbooks \
		/usr/share/breakglass/runbooks/upstream /usr/share/breakglass/runbooks/upstream/network-debug \
		/usr/share/breakglass/runbooks/internal \
	&& test -x /usr/bin/tcpdump

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
