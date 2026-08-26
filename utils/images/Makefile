# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

.PHONY: test shellcheck integration multiarch

test:
	./storage-debug/tests/test.sh
	./dump-reader/tests/test.sh

shellcheck:
	shellcheck storage-debug/bin/storage-report storage-debug/tests/test.sh \
		dump-reader/bin/dump-reader dump-reader/tests/test.sh tests/integration.sh

integration:
	./tests/integration.sh

multiarch:
	@set -eu; \
	archives=; \
	cleanup() { for archive in $$archives; do rm -f "$$archive"; done; }; \
	trap cleanup EXIT HUP INT TERM; \
	for image in storage-debug dump-reader; do \
		archive=$$(mktemp "$${TMPDIR:-/tmp}/$${image}.XXXXXX.oci.tar"); \
		archives="$$archives $$archive"; \
		docker buildx build --platform linux/amd64,linux/arm64 \
			--output "type=oci,dest=$$archive" "$$image"; \
	done
