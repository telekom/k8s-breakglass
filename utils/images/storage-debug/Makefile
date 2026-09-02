# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

SHELL := /bin/sh

IMAGE ?= ghcr.io/telekom/k8s-breakglass/utils/storage-debug:dev
PLATFORM ?= linux/amd64

.PHONY: test package-contract-test kind-contract-test build integration shellcheck

test:
	./tests/test-package-contract.sh
	./tests/test.sh

package-contract-test:
	./tests/test-package-contract.sh

kind-contract-test:
	./tests/test-kind-kubestr-contract.sh

build:
	docker build --pull=false --platform "$(PLATFORM)" --tag "$(IMAGE)" .

integration:
	./tests/integration.sh

shellcheck:
	shellcheck bin/storage-report bin/storage-diagnostics tests/test.sh tests/integration.sh tests/kind-kubestr.sh
