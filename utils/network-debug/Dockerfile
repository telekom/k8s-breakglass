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

# pwru and its Go module graph come from pwru/go.mod and pwru/go.sum, which
# Dependabot tracks; go.sum authenticates every downloaded module, including
# pwru itself. The build fails if go.sum lacks an entry or if pwru's own
# replace directives are not mirrored in pwru/go.mod. The unpacked pwru module
# replaces only itself, so the binary links exactly the tracked graph (checked
# below) and dependency bumps (for example golang.org/x/net) need no Dockerfile
# edits. pwru's own Makefile builds the static libpcap and runs its bpf2go code
# generation; the build flags mirror its `pwru` target. The compiler and build
# dependencies never enter the runtime image. Storage tooling is intentionally
# excluded; kubestr belongs to storage-debug.
FROM golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d AS tools
ARG TARGETARCH

COPY pwru/go.mod pwru/go.sum /src/tools/
WORKDIR /src/tools

# The build-only clang/llvm/flex/bison packages follow the digest-pinned
# builder's Debian release.
# hadolint ignore=DL3008
RUN set -eux; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update; \
	apt-get install --no-install-recommends --yes clang llvm flex bison; \
	rm -rf /var/lib/apt/lists/*; \
	cp go.sum /tmp/tracked-go.sum; \
	go mod download github.com/cilium/pwru; \
	pwru_version="$(go list -m -f '{{.Version}}' github.com/cilium/pwru)"; \
	go list -m -f '{{.Path}} {{.Version}}' all > /tmp/tracked-modules; \
	mkdir -p /src/pwru /out; \
	cp -a "$(go list -m -f '{{.Dir}}' github.com/cilium/pwru)/." /src/pwru/; \
	chmod -R u+w /src/pwru; \
	chmod +x /src/pwru/libpcap/configure; \
	sed -n 's/^replace //; s/^[[:space:]]*//; /=>/p' /src/pwru/go.mod > /tmp/upstream-replaces; \
	sed -n 's/^replace //; s/^[[:space:]]*//; /=>/p' go.mod > /tmp/tracked-replaces; \
	cmp /tmp/upstream-replaces /tmp/tracked-replaces || { echo "pwru replace directives differ from pwru/go.mod" >&2; exit 1; }; \
	make -C /src/pwru libpcap/libpcap.a; \
	TARGET_GOARCH="${TARGETARCH:-amd64}" go -C /src/pwru generate; \
	go mod edit -replace github.com/cilium/pwru=/src/pwru; \
	CGO_ENABLED=1 GOARCH="${TARGETARCH:-amd64}" go build \
		-ldflags "-w -s -X 'github.com/cilium/pwru/internal/pwru.Version=${pwru_version}'" \
		-o /out/pwru github.com/cilium/pwru; \
	cmp go.sum /tmp/tracked-go.sum || { echo "pwru/go.sum is incomplete; run go mod tidy in utils/network-debug/pwru" >&2; exit 1; }; \
	go version -m /out/pwru > /out/pwru-build-info; \
	awk 'NR == FNR { tracked[$1] = $2; next } ($1 == "dep" || $1 == "mod") && tracked[$2] != $3 { print "linked " $2 " " $3 " differs from pwru/go.mod"; bad = 1 } END { exit bad }' \
		/tmp/tracked-modules /out/pwru-build-info

FROM runtime

ARG VERSION=0.1.0
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG NETSHOOT_ALPINE_VERSION=3.24

# The pinned netshoot image owns the runtime package set. Refresh it from the
# matching Alpine 3.24 repositories to consume security fixes, record the
# installed package versions, then prove the expected Alpine runtime before
# removing optional inherited binaries.
RUN set -eux; \
	sed -i '/\/alpine\/edge\//d' /etc/apk/repositories; \
	printf '%s\n' \
		'https://dl-cdn.alpinelinux.org/alpine/v3.24/main' \
		'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' \
		>> /etc/apk/repositories; \
	apk update; \
	apk upgrade; \
	install -d /usr/share/breakglass; \
	apk list --installed --no-network > /usr/share/breakglass/installed-packages 2>/dev/null; \
	grep -q '^tcpdump-' /usr/share/breakglass/installed-packages; \
	chmod 0444 /usr/share/breakglass/installed-packages; \
	rm -rf /var/cache/apk/*; \
	case "$(cat /etc/alpine-release)" in "${NETSHOOT_ALPINE_VERSION}".*) ;; *) exit 1 ;; esac; \
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
COPY --from=tools /out/pwru-build-info /usr/share/breakglass/pwru-build-info
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
