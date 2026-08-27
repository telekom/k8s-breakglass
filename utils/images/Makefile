# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

.PHONY: test storage-test dump-test oci-attestation-test shellcheck integration multiarch

test: storage-test dump-test

storage-test:
	./storage-debug/tests/test.sh

dump-test:
	./dump-reader/tests/test.sh

oci-attestation-test:
	./tests/verify-oci-attestations-test.sh

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
			--provenance=true --sbom=true \
			--output "type=oci,dest=$$archive" "$$image"; \
		ruby tests/verify-oci-attestations.rb "$$archive"; \
	done
