# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

.PHONY: test shellcheck

test:
	./storage-debug/tests/test.sh
	./dump-reader/tests/test.sh

shellcheck:
	shellcheck storage-debug/bin/storage-report storage-debug/tests/test.sh \
		dump-reader/bin/dump-reader dump-reader/tests/test.sh
