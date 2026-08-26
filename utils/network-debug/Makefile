# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

IMAGE ?= ghcr.io/telekom/k8s-breakglass-network-debug
VERSION ?= 0.1.0
VCS_REF ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf 'unknown')
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: help build build-multiarch test

help: ## List image targets.
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build a local image for the host architecture.
	docker build --file Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg VCS_REF=$(VCS_REF) --build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(IMAGE):$(VERSION) .

build-multiarch: ## Build a multi-architecture image with SBOM/provenance attestations.
	docker buildx build --platform $(PLATFORMS) --file Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg VCS_REF=$(VCS_REF) --build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(IMAGE):$(VERSION) --sbom=true --provenance=mode=max --push .

test: ## Run static helper and Dockerfile checks.
	./tests/test.sh
