# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# netshoot v0.16 supplies the overlapping network troubleshooting tools. Keep
# the release tag and immutable multi-architecture manifest digest together.
# The upstream package set is inherited as a unit and refreshed from the
# pinned Alpine 3.24 repositories before adding pwru and the contract/docs.
FROM ghcr.io/nicolaka/netshoot:v0.16@sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70 AS runtime

ARG VERSION=0.1.0
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

# pwru is built from its immutable Go module version with the pinned builder.
# The compiler and build dependencies never enter the runtime image. Storage
# tooling is intentionally excluded; kubestr belongs to storage-debug.
FROM golang:1.27@sha256:4013ae0f9e7994f8535c58c811f8f863fbed38b72e0d51e6592156f758d66146 AS tools
ARG TARGETARCH
ARG PWRU_VERSION=v1.0.12
ARG PWRU_MODULE_SUM=h1:a8oQXdTJHznh4vCI3GLf31IDqGYIUmDJzjSaXHYpQPg=
ARG PWRU_COMMIT=f1d6cf8898953ac1560401e181f3ac5f0e33b486

RUN set -eux; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update; \
	apt-get install --no-install-recommends --yes clang llvm flex bison; \
	rm -rf /var/lib/apt/lists/*; \
	module_json="$(go mod download -json "github.com/cilium/pwru@${PWRU_VERSION}")"; \
	printf '%s\n' "${module_json}" | grep -F '"Sum": "'"${PWRU_MODULE_SUM}"'"'; \
	printf '%s\n' "${module_json}" | grep -F '"Hash": "'"${PWRU_COMMIT}"'"'; \
	mkdir -p /src/pwru /out; \
	cp -a "$(go env GOPATH)/pkg/mod/github.com/cilium/pwru@${PWRU_VERSION}/." /src/pwru/; \
	test "$(grep '^go ' /src/pwru/go.mod | awk '{print $2}')" = "1.25.0"; \
	chmod +x /src/pwru/libpcap/configure; \
	cd /src/pwru; \
	make VERSION="${PWRU_VERSION}" TARGET_GOARCH="${TARGETARCH:-amd64}" GOARCH="${TARGETARCH:-amd64}" pwru; \
	install -m 0755 pwru /out/pwru

FROM runtime

ARG VERSION=0.1.0
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG PWRU_VERSION=v1.0.12
ARG NETSHOOT_ALPINE_VERSION=3.24.1

# The pinned netshoot image owns the runtime package set. Refresh it from the
# matching Alpine 3.24 repositories to consume security fixes, then prove the
# expected Alpine runtime before removing optional inherited binaries.
RUN set -eux; \
	sed -i '/\/alpine\/edge\//d' /etc/apk/repositories; \
	printf '%s\n' \
		'https://dl-cdn.alpinelinux.org/alpine/v3.24/main' \
		'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' \
		>> /etc/apk/repositories; \
	apk update; \
	apk upgrade; \
	test "$(cat /etc/alpine-release)" = "${NETSHOOT_ALPINE_VERSION}"; \
	test -x /usr/bin/tcpdump; \
	rm -f /usr/local/bin/calicoctl /usr/local/bin/ctop /usr/local/bin/fortio \
	/usr/local/bin/grpcurl /usr/local/bin/termshark

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

COPY --from=tools /out/pwru /usr/local/bin/pwru
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
