# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

IMAGE ?= ghcr.io/telekom/k8s-breakglass/utils/network-debug
VERSION ?= 0.1.0
VCS_REF ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf 'unknown')
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: help build build-multiarch test integration pod-capture-integration sbom sign

OCI_ARCHIVE ?= network-debug.oci.tar

help: ## List image targets.
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build a local image for the host architecture.
	docker build --file Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg VCS_REF=$(VCS_REF) --build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(IMAGE):$(VERSION) .

build-multiarch: ## Build a local multi-architecture OCI archive with SBOM/provenance attestations.
	docker buildx build --platform $(PLATFORMS) --file Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg VCS_REF=$(VCS_REF) --build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(IMAGE):$(VERSION) --sbom=true --provenance=mode=max \
		--output type=oci,dest=$(OCI_ARCHIVE) .

sbom: ## Attest an SPDX SBOM to an immutable image digest.
	@test -n "$(DIGEST)" || (printf '%s\n' 'DIGEST is required' >&2; exit 2)
	@test -n "$(SBOM)" || (printf '%s\n' 'SBOM is required' >&2; exit 2)
	cosign attest --yes --type spdxjson --predicate "$(SBOM)" "$(IMAGE)@$(DIGEST)"

sign: ## Sign an immutable image digest with keyless cosign.
	@test -n "$(DIGEST)" || (printf '%s\n' 'DIGEST is required' >&2; exit 2)
	cosign sign --yes "$(IMAGE)@$(DIGEST)"

test: ## Run hermetic helper behavior checks.
	go -C cmd/pod-netns-capture test ./...
	./tests/test.sh
	./tests/test-kind-ownership.sh
	./tests/test-pwru-lifecycle.sh

integration: ## Run real tool proofs in disposable Docker and kind resources.
	./tests/integration.sh

pod-capture-integration: ## Prove exact selected-pod netns capture and cleanup on Linux/kind.
	./tests/pod-netns-capture-integration.sh
