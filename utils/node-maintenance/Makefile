# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

SHELL := /bin/sh

IMAGE ?= ghcr.io/telekom/k8s-breakglass/node-maintenance:dev
PLATFORMS ?= linux/amd64,linux/arm64
VERSION ?= dev
VCS_REF ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
OCI_ARCHIVE ?= node-maintenance.oci.tar

.PHONY: test integration build build-multiarch sbom sign

test:
	./tests/test-helpers.sh

integration:
	./tests/integration.sh

build:
	docker build --pull=false \
		--build-arg VERSION=$(VERSION) \
		--build-arg VCS_REF=$(VCS_REF) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE) .

build-multiarch:
	docker buildx build --pull=false --platform $(PLATFORMS) \
		--provenance=true --sbom=true \
		--build-arg VERSION=$(VERSION) \
		--build-arg VCS_REF=$(VCS_REF) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--output=type=oci,dest=$(OCI_ARCHIVE) \
		-t $(IMAGE) .

# Signing and attestation are intentionally separate from the build. Release
# automation must sign the immutable registry digest, never a mutable tag.
sbom:
	@test -n "$(DIGEST)" || (printf '%s\n' 'DIGEST is required' >&2; exit 2)
	@case "$(DIGEST)" in sha256:*) ;; *) printf '%s\n' 'DIGEST must be an immutable sha256 digest' >&2; exit 2;; esac
	@test -n "$(SBOM)" || (printf '%s\n' 'SBOM is required' >&2; exit 2)
	cosign attest --yes --type spdxjson --predicate "$(SBOM)" "$(IMAGE)@$(DIGEST)"

sign:
	@test -n "$(DIGEST)" || (printf '%s\n' 'DIGEST is required' >&2; exit 2)
	@case "$(DIGEST)" in sha256:*) ;; *) printf '%s\n' 'DIGEST must be an immutable sha256 digest' >&2; exit 2;; esac
	cosign sign --yes "$(IMAGE)@$(DIGEST)"
