#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Negative contract for hack/validate-image-metadata.rb dependency entries:
# each mutation of the storage-debug metadata must be rejected.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
metadata="${root}/utils/images/storage-debug/image-metadata.yaml"
work=$(mktemp -d)
trap 'rm -rf -- "${work}"' EXIT

ruby "${root}/hack/validate-image-metadata.rb" "${metadata}" >/dev/null

# Each case replaces the dependency list with one entry (YAML flow mapping).
cases=(
	'{name: fio, version: 1.0, versionSource: /usr/share/breakglass/installed-packages}'
	'{name: fio}'
	'{name: fio, version: ""}'
	'{name: fio, versionSource: /etc/passwd}'
	'{name: fio, versionSource: ../dump-reader/Dockerfile}'
	'{name: fio, versionSource: missing/go.mod}'
	'{name: example.com/not-required, versionSource: kubestr/go.mod}'
	'{name: github.com/graymeta/stow, versionSource: kubestr/go.mod}'
	'{name: fio, versionSource: Dockerfile}'
	'{name: github.com/kastenhq/kubestr, versionSource: kubestr/go.sum}'
)
for entry in "${cases[@]}"; do
	mutated="${work}/image-metadata.yaml"
	ruby -ryaml -e '
		doc = YAML.safe_load(File.read(ARGV[0]))
		doc["dependencies"] = [YAML.safe_load(ARGV[1])]
		File.write(ARGV[2], YAML.dump(doc))
	' "${metadata}" "${entry}" "${mutated}"
	if ruby "${root}/hack/validate-image-metadata.rb" "${mutated}" >/dev/null 2>&1; then
		printf 'image metadata validator accepted invalid dependency %s\n' "${entry}" >&2
		exit 1
	fi
done
printf '%s\n' 'image metadata validator negative contract passed'
