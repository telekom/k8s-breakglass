#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Behavioral test for retry and fail-closed registry digest resolution. The
# fake Docker command models registry responses; it does not inspect scripts
# or assert that particular strings are present in them.

set -Eeuo pipefail

test_dir="$(mktemp -d)"
trap 'rm -rf "${test_dir}"' EXIT
mkdir -p "${test_dir}/bin"
cat >"${test_dir}/bin/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -Eeuo pipefail
state="${FAKE_DOCKER_STATE:?}"
count=0
[[ -f "${state}" ]] && count="$(cat "${state}")"
count=$((count + 1))
printf '%s\n' "${count}" >"${state}"
if [[ "${FAKE_DOCKER_MODE}" == transient-success && "${count}" -lt 3 ]]; then
  echo 'temporary registry unavailable' >&2
  exit 1
fi
if [[ "${FAKE_DOCKER_MODE}" == auth-failure ]]; then
  echo 'denied: requested access to the resource is denied' >&2
  exit 1
fi
printf 'Name: example.invalid/utility:dev\nDigest: sha256:%064d\n' 0 1
FAKE_DOCKER
chmod +x "${test_dir}/bin/docker"

export PATH="${test_dir}/bin:${PATH}"
export FAKE_DOCKER_STATE="${test_dir}/state"
export REGISTRY_DIGEST_ATTEMPTS=4
export REGISTRY_DIGEST_DELAY_SECONDS=0
export FAKE_DOCKER_MODE=transient-success
resolved="$(hack/resolve-registry-digest.sh example.invalid/utility:dev)"
[[ "${resolved}" == sha256:$(printf '%064d' 0) ]] || {
  echo "transient failure was not retried to a valid digest" >&2
  exit 1
}
[[ "$(cat "${FAKE_DOCKER_STATE}")" == 3 ]] || {
  echo "unexpected number of registry probes" >&2
  exit 1
}

: >"${FAKE_DOCKER_STATE}"
export FAKE_DOCKER_MODE=auth-failure
if hack/resolve-registry-digest.sh example.invalid/utility:dev >/dev/null 2>"${test_dir}/auth-error"; then
  echo "authentication failure was incorrectly accepted" >&2
  exit 1
fi
[[ "$(cat "${FAKE_DOCKER_STATE}")" == 4 ]] || {
  echo "bounded retry count was not enforced" >&2
  exit 1
}

echo "registry digest resolution behavior passed"
