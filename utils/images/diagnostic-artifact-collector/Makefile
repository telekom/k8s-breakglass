# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

.PHONY: test uploader-test copier-test image-test kind-test shellcheck

test: uploader-test copier-test image-test

uploader-test:
	go test ./uploader

copier-test:
	go test ./copier

image-test:
	./tests/test.sh

kind-test:
	./tests/kind-emptydir.sh

shellcheck:
	shellcheck bin/diagnostic-artifact-collector tests/test.sh tests/kind-emptydir.sh
