# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

SHELL := /bin/sh

IMAGE ?= ghcr.io/telekom/k8s-breakglass/storage-debug:dev
PLATFORM ?= linux/amd64

.PHONY: test build integration shellcheck

test:
	./tests/test.sh

build:
	docker build --pull=false --platform "$(PLATFORM)" --tag "$(IMAGE)" .

integration:
	./tests/integration.sh

shellcheck:
	shellcheck bin/storage-report bin/storage-diagnostics tests/test.sh tests/integration.sh tests/kind-kubestr.sh
