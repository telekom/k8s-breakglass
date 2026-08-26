# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

SHELL := /bin/sh

IMAGE ?= ghcr.io/telekom/breakglass-workload-debug:dev
PLATFORMS ?= linux/amd64,linux/arm64
VERSION ?= dev
VCS_REF ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: test integration-test build build-multiarch sbom sign

OCI_ARCHIVE ?= workload-debug.oci.tar

test:
	./tests/test_helpers.sh

integration-test:
	./tests/test_integration.sh

build:
	docker build --pull=false \
		--build-arg "VERSION=$(VERSION)" --build-arg "VCS_REF=$(VCS_REF)" --build-arg "BUILD_DATE=$(BUILD_DATE)" \
		--tag "$(IMAGE)" .

build-multiarch:
	docker buildx build --pull=false --platform "$(PLATFORMS)" \
		--provenance=true --sbom=true \
		--build-arg "VERSION=$(VERSION)" --build-arg "VCS_REF=$(VCS_REF)" --build-arg "BUILD_DATE=$(BUILD_DATE)" \
		--output "type=oci,dest=$(OCI_ARCHIVE)" --tag "$(IMAGE)" .

sbom:
	@test -n "$(DIGEST)" || (printf '%s\n' 'DIGEST is required' >&2; exit 2)
	@test -n "$(SBOM)" || (printf '%s\n' 'SBOM is required' >&2; exit 2)
	cosign attest --yes --type spdxjson --predicate "$(SBOM)" "$(IMAGE)@$(DIGEST)"

sign:
	@test -n "$(DIGEST)" || (printf '%s\n' 'DIGEST is required' >&2; exit 2)
	cosign sign --yes "$(IMAGE)@$(DIGEST)"
