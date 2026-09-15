# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

.PHONY: test uploader-test copier-test image-test bounded-cleanup-contract-test kind-test kind-collision-test kind-contract-test kind-collision-contract-test shellcheck

test: uploader-test copier-test image-test bounded-cleanup-contract-test

uploader-test:
	go test ./uploader

copier-test:
	go test ./copier

image-test:
	./tests/test.sh

bounded-cleanup-contract-test:
	./tests/test-bounded-cleanup-contract.sh

kind-test:
	./tests/kind-emptydir.sh

kind-collision-test:
	./tests/kind-collision.sh

kind-collision-contract-test:
	./tests/test-kind-collision-contract.sh

kind-contract-test:
	./tests/test-kind-emptydir-contract.sh

shellcheck:
	shellcheck bin/diagnostic-artifact-collector tests/test.sh tests/bounded-container-cleanup.sh tests/test-bounded-cleanup-contract.sh tests/kind-emptydir.sh tests/kind-collision.sh \
		tests/test-kind-emptydir-contract.sh tests/test-kind-collision-contract.sh
