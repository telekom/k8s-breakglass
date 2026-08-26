#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Behavioral regression tests for rerun-safe Helm publication. The release
# workflow delegates to the tested script; this test intentionally does not
# inspect workflow source text.

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "${test_dir}"' EXIT

mkdir -p "${test_dir}/bin" "${test_dir}/charts"
touch "${test_dir}/charts/debug-session-catalogue-0.2.0.tgz"

cat >"${test_dir}/bin/helm" <<'EOF'
#!/usr/bin/env bash
set -eu
if [ "$1 $2" = "show chart" ]; then
  ref="$3"
  if [[ "${ref}" == *.tgz ]]; then
    printf 'name: debug-session-catalogue\nversion: 0.2.0\n'
    [ "${FAKE_LOCAL_METADATA:-complete}" = complete ] && printf 'appVersion: "%s"\n' "${FAKE_LOCAL_APP_VERSION:-v1.2.3}"
    exit 0
  fi
  case "${FAKE_REMOTE_MODE:-missing}" in
    matching) printf 'name: debug-session-catalogue\nversion: 0.2.0\nappVersion: "%s"\n' "${FAKE_LOCAL_APP_VERSION:-v1.2.3}" ;;
    mismatch) printf 'name: debug-session-catalogue\nversion: 0.2.0\nappVersion: "v9.9.9"\n' ;;
    incomplete) printf 'name: debug-session-catalogue\nversion: 0.2.0\n' ;;
    missing) echo 'Error: manifest unknown' >&2; exit 1 ;;
    network) echo 'Error: lookup ghcr.io: no such host' >&2; exit 7 ;;
  esac
  exit 0
fi
if [ "$1" = push ]; then
  printf '%s\n' "$*" >>"${FAKE_HELM_LOG:?}"
  exit 0
fi
exit 64
EOF
chmod +x "${test_dir}/bin/helm"

run_publish() {
  PATH="${test_dir}/bin:${PATH}" FAKE_HELM_LOG="${test_dir}/helm.log" \
    "${script_dir}/publish-helm-charts.sh" "${test_dir}/charts" \
    oci://ghcr.io/example/charts v1.2.3
}

: >"${test_dir}/helm.log"
FAKE_REMOTE_MODE=missing run_publish >/dev/null
[ "$(wc -l <"${test_dir}/helm.log" | tr -d ' ')" -eq 1 ] || {
  echo "missing chart was not pushed exactly once" >&2
  exit 1
}

: >"${test_dir}/helm.log"
FAKE_REMOTE_MODE=matching run_publish >/dev/null
[ ! -s "${test_dir}/helm.log" ] || {
  echo "matching published chart was pushed again" >&2
  exit 1
}

for mode in mismatch incomplete network; do
  : >"${test_dir}/helm.log"
  if FAKE_REMOTE_MODE="${mode}" run_publish >/dev/null 2>&1; then
    echo "remote ${mode} condition did not fail closed" >&2
    exit 1
  fi
  [ ! -s "${test_dir}/helm.log" ] || {
    echo "remote ${mode} condition attempted a push" >&2
    exit 1
  }
done

if FAKE_REMOTE_MODE=missing FAKE_LOCAL_APP_VERSION=v2.0.0 run_publish >/dev/null 2>&1; then
  echo "release/appVersion mismatch did not fail closed" >&2
  exit 1
fi
if FAKE_REMOTE_MODE=missing FAKE_LOCAL_METADATA=incomplete run_publish >/dev/null 2>&1; then
  echo "incomplete packaged chart metadata did not fail closed" >&2
  exit 1
}
[ "$(ruby "${script_dir}/canonical-helm-chart-digest.rb" "${test_dir}/charts/debug-session-catalogue-0.2.0.tgz")" = \
  "$(ruby "${script_dir}/canonical-helm-chart-digest.rb" "${test_dir}/timestamp.tgz")" ] || {
  echo "timestamp fixture changed canonical chart content" >&2
  exit 1
}
[ "$(ruby "${script_dir}/canonical-helm-chart-digest.rb" "${test_dir}/charts/debug-session-catalogue-0.2.0.tgz")" != \
  "$(ruby "${script_dir}/canonical-helm-chart-digest.rb" "${test_dir}/changed.tgz")" ] || {
  echo "changed-content fixture did not change canonical chart content" >&2
  exit 1
}

cat >"${test_dir}/bin/helm" <<'EOF'
#!/usr/bin/env bash
set -eu
if [ "$1 $2" = "show chart" ]; then
  printf '%s\n' "$*" >>"${FAKE_HELM_CALL_LOG:?}"
  ref="$3"
  if [[ "${ref}" == *.tgz ]]; then
    printf 'name: debug-session-catalogue\nversion: 0.2.0\n'
    [ "${FAKE_LOCAL_METADATA:-complete}" = complete ] && printf 'appVersion: "%s"\n' "${FAKE_LOCAL_APP_VERSION:-v1.2.3}"
    exit 0
  fi
  case "${FAKE_REMOTE_MODE:-missing}" in
    matching|timestamp-different|different) printf 'name: debug-session-catalogue\nversion: 0.2.0\nappVersion: "%s"\n' "${FAKE_LOCAL_APP_VERSION:-v1.2.3}" ;;
    mismatch) printf 'name: debug-session-catalogue\nversion: 0.2.0\nappVersion: "v9.9.9"\n' ;;
    incomplete) printf 'name: debug-session-catalogue\nversion: 0.2.0\n' ;;
    missing) echo 'Error: manifest unknown' >&2; exit 1 ;;
    network) echo 'Error: lookup ghcr.io: no such host' >&2; exit 7 ;;
  esac
  exit 0
fi

echo "Release publication behavior passed"
