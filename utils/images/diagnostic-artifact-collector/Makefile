# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

.PHONY: test uploader-test copier-test image-test shellcheck

test: uploader-test copier-test image-test

uploader-test:
	go test ./uploader

copier-test:
	go test ./copier

image-test:
	./tests/test.sh

shellcheck:
	shellcheck bin/diagnostic-artifact-collector tests/test.sh
