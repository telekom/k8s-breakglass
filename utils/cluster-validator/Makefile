# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

ROOT_DIR := $(abspath ../..)
IMAGE ?= ghcr.io/telekom/k8s-breakglass-cluster-validator:dev
PLATFORMS ?= linux/amd64,linux/arm64
VERSION ?= dev
GIT_COMMIT ?= $(shell git -C $(ROOT_DIR) rev-parse --short HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
OCI_ARCHIVE ?= cluster-validator.oci.tar

.PHONY: test build build-multiarch

test:
	$(MAKE) -C $(ROOT_DIR) test-validator

build:
	docker build --pull=false -f Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) -t $(IMAGE) $(ROOT_DIR)

build-multiarch:
	docker buildx build --pull=false --platform $(PLATFORMS) -f Dockerfile \
		--provenance=true --sbom=true \
		--build-arg VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--output=type=oci,dest=$(OCI_ARCHIVE) -t $(IMAGE) $(ROOT_DIR)
