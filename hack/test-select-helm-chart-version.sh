#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "${test_dir}"' EXIT

mkdir -p "${test_dir}/bin" "${test_dir}/chart"
cat >"${test_dir}/chart/Chart.yaml" <<'EOF'
apiVersion: v2
name: test-chart
version: 0.4.8
appVersion: "0.2.0"
EOF
cat >"${test_dir}/registry.json" <<'EOF'
{"auths":{"ghcr.io":{"auth":"dXNlcjpwYXNz"}}}
EOF
cat >"${test_dir}/bin/helm" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [ "${1:-} ${2:-}" = "show chart" ]; then
  ref="${3:?}"
  if [ "${ref}" = "${TEST_CHART_DIR:?}" ]; then
    cat "${ref}/Chart.yaml"
    exit 0
  fi
  version="${5:?}"
  case "${FAKE_TAG_MODE:?}:${version}" in
    gap:0.4.8|gap:0.4.10) app=v0.3.0-rc.16 ;;
    baseline:0.4.8) app=v0.3.0-rc.16 ;;
    occupied:0.4.8) app=v0.3.0-rc.16 ;;
    prerelease:0.4.9-rc.1) app=v0.3.0-rc.17 ;;
    semver:0.4.9-alpha.10) app=v0.3.0-rc.10 ;;
    semver:0.4.9-alpha.2) app=v0.3.0-rc.2 ;;
    build:0.4.9_build.1) app=v0.3.0-rc.16 ;;
    buildrerun:0.4.9_build.1) app=v0.3.0-rc.17 ;;
    rerun:0.4.8) app=v0.3.0-rc.17 ;;
    rerun:0.4.10) app=v0.3.0-rc.18 ;;
    *) echo "unexpected chart lookup: ${version}" >&2; exit 64 ;;
  esac
  printf 'name: test-chart\nversion: %s\nappVersion: "%s"\n' "${version}" "${app}"
  exit 0
fi
echo "unexpected helm invocation: $*" >&2
exit 64
EOF
cat >"${test_dir}/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
url="${@: -1}"
headers=''
body=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -D) headers="$2"; shift 2 ;;
    -o) body="$2"; shift 2 ;;
    -w) shift 2 ;;
    *) shift ;;
  esac
done
if [ "${FAKE_CURL_MODE:-ok}" = network ]; then exit 7; fi
if [[ "${url}" == *'/tags/list?n=1' ]]; then
  printf 'HTTP/2 401\nwww-authenticate: Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:test/charts/test-chart:pull"\n\n' >"${headers}"
  printf 'unauthorized\n' >"${body}"
  printf '401'
elif [[ "${url}" == *'/token?'* ]]; then
  printf '{"token":"registry-token"}'
elif [[ "${url}" == *'last='* ]]; then
  if [ "${FAKE_TAG_MODE:-ok}" = loop ]; then
    printf 'HTTP/2 200\nlink: </v2/test/charts/test-chart/tags/list?n=100&last=0.4.9>; rel="next"\n\n' >"${headers}"
  else
    printf 'HTTP/2 200\n\n' >"${headers}"
  fi
  printf '{"tags":["0.4.10"]}' >"${body}"
else
  printf 'HTTP/2 200\nlink: </v2/test/charts/test-chart/tags/list?n=100&last=0.4.9>; rel="next"\n\n' >"${headers}"
  case "${FAKE_TAG_MODE:?}" in
    gap) printf '{"tags":["0.4.8","0.4.10","sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.sig","sha256-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.att"]}' >"${body}" ;;
    baseline) printf '{"tags":["0.4.8"]}' >"${body}"; sed -i.bak '/^link:/d' "${headers}"; rm -f "${headers}.bak" ;;
    occupied) printf '{"tags":["0.4.8"]}' >"${body}"; sed -i.bak '/^link:/d' "${headers}"; rm -f "${headers}.bak" ;;
    prerelease) printf '{"tags":["0.4.9-rc.1"]}' >"${body}"; sed -i.bak '/^link:/d' "${headers}"; rm -f "${headers}.bak" ;;
    semver) printf '{"tags":["0.4.9-alpha.10","0.4.9-alpha.2"]}' >"${body}"; sed -i.bak '/^link:/d' "${headers}"; rm -f "${headers}.bak" ;;
    build) printf '{"tags":["0.4.9_build.1"]}' >"${body}"; sed -i.bak '/^link:/d' "${headers}"; rm -f "${headers}.bak" ;;
    buildrerun) printf '{"tags":["0.4.9_build.1"]}' >"${body}"; sed -i.bak '/^link:/d' "${headers}"; rm -f "${headers}.bak" ;;
    malformed) printf '{"tags":["0.4.8","latest"]}' >"${body}"; sed -i.bak '/^link:/d' "${headers}"; rm -f "${headers}.bak" ;;
    rerun) printf '{"tags":["0.4.8","0.4.10"]}' >"${body}" ;;
    external) printf '{"tags":["0.4.8"]}' >"${body}"; sed -i.bak 's#</v2#<https://evil.example/v2#' "${headers}"; rm -f "${headers}.bak" ;;
    loop) printf '{"tags":["0.4.8"]}' >"${body}"; sed -i.bak 's#last=0.4.9#last=0.4.9#' "${headers}"; rm -f "${headers}.bak" ;;
  esac
fi
EOF
chmod +x "${test_dir}/bin/helm" "${test_dir}/bin/curl"

run_selector() {
  PATH="${test_dir}/bin:${PATH}" HELM_REGISTRY_CONFIG="${test_dir}/registry.json" \
    TEST_CHART_DIR="${test_dir}/chart" FAKE_TAG_MODE="${1}" \
    "${script_dir}/select-helm-chart-version.sh" "${test_dir}/chart" \
    oci://ghcr.io/test/charts "${2}" >/dev/null
}

run_selector gap v0.3.0-rc.18
[ "$(awk '$1 == "version:" {print $2}' "${test_dir}/chart/Chart.yaml")" = 0.4.11 ] || {
  echo "selector did not advance beyond the authoritative maximum" >&2
  exit 1
}

sed -E -i.bak 's/^version: .*/version: 1.0.0/' "${test_dir}/chart/Chart.yaml"
rm -f "${test_dir}/chart/Chart.yaml.bak"
run_selector baseline v0.3.0-rc.18
[ "$(awk '$1 == "version:" {print $2}' "${test_dir}/chart/Chart.yaml")" = 1.0.0 ] || {
  echo "source chart baseline was not preserved" >&2
  exit 1
}
sed -E -i.bak 's/^version: .*/version: 0.4.8/' "${test_dir}/chart/Chart.yaml"
rm -f "${test_dir}/chart/Chart.yaml.bak"

run_selector occupied v0.3.0-rc.18
[ "$(awk '$1 == "version:" {print $2}' "${test_dir}/chart/Chart.yaml")" = 0.4.9 ] || {
  echo "occupied source version was reused for a new release" >&2
  exit 1
}

sed -E -i.bak 's/^version: .*/version: 0.4.8/' "${test_dir}/chart/Chart.yaml"
rm -f "${test_dir}/chart/Chart.yaml.bak"
run_selector prerelease v0.3.0
[ "$(awk '$1 == "version:" {print $2}' "${test_dir}/chart/Chart.yaml")" = 0.4.9 ] || {
  echo "stable chart did not follow a prerelease at the same base version" >&2
  exit 1
}

sed -E -i.bak 's/^version: .*/version: 0.4.8/' "${test_dir}/chart/Chart.yaml"
rm -f "${test_dir}/chart/Chart.yaml.bak"
run_selector semver v0.3.0-rc.10
[ "$(awk '$1 == "version:" {print $2}' "${test_dir}/chart/Chart.yaml")" = 0.4.9-alpha.10 ] || {
  echo "SemVer prerelease identifiers were not numerically ordered" >&2
  exit 1
}

sed -E -i.bak 's/^version: .*/version: 0.4.8/' "${test_dir}/chart/Chart.yaml"
rm -f "${test_dir}/chart/Chart.yaml.bak"
run_selector build v0.3.0-rc.18
[ "$(awk '$1 == "version:" {print $2}' "${test_dir}/chart/Chart.yaml")" = 0.4.10 ] || {
  echo "occupied build-metadata chart tag was not advanced" >&2
  exit 1
}

cat >"${test_dir}/chart/Chart.yaml" <<'EOF'
apiVersion: v2
name: test-chart
version: 0.4.9+build.1
appVersion: "0.2.0"
EOF
run_selector buildrerun v0.3.0-rc.17
[ "$(awk '$1 == "version:" {print $2}' "${test_dir}/chart/Chart.yaml")" = 0.4.9+build.1 ] || {
  echo "build-metadata release rerun did not preserve the exact chart version" >&2
  exit 1
}
sed -E -i.bak 's/^version: .*/version: 0.4.8/' "${test_dir}/chart/Chart.yaml"
rm -f "${test_dir}/chart/Chart.yaml.bak"

sed -E -i.bak 's/^version: .*/version: 0.4.8/' "${test_dir}/chart/Chart.yaml"
rm -f "${test_dir}/chart/Chart.yaml.bak"
run_selector rerun v0.3.0-rc.17
[ "$(awk '$1 == "version:" {print $2}' "${test_dir}/chart/Chart.yaml")" = 0.4.8 ] || {
  echo "exact-release rerun did not reuse its lower published version" >&2
  exit 1
}

if PATH="${test_dir}/bin:${PATH}" HELM_REGISTRY_CONFIG="${test_dir}/registry.json" \
  TEST_CHART_DIR="${test_dir}/chart" FAKE_TAG_MODE=network \
  FAKE_CURL_MODE=network "${script_dir}/select-helm-chart-version.sh" \
  "${test_dir}/chart" oci://ghcr.io/test/charts v0.3.0 >/dev/null 2>&1; then
  echo "registry network failure did not fail closed" >&2
  exit 1
fi

for mode in external loop; do
  if PATH="${test_dir}/bin:${PATH}" HELM_REGISTRY_CONFIG="${test_dir}/registry.json" \
    TEST_CHART_DIR="${test_dir}/chart" FAKE_TAG_MODE="${mode}" \
    "${script_dir}/select-helm-chart-version.sh" "${test_dir}/chart" \
    oci://ghcr.io/test/charts v0.3.0 >/dev/null 2>&1; then
    echo "registry ${mode} pagination did not fail closed" >&2
    exit 1
  fi
done

if PATH="${test_dir}/bin:${PATH}" HELM_REGISTRY_CONFIG="${test_dir}/registry.json" \
  TEST_CHART_DIR="${test_dir}/chart" FAKE_TAG_MODE=malformed \
  "${script_dir}/select-helm-chart-version.sh" "${test_dir}/chart" \
  oci://ghcr.io/test/charts v0.3.0 >/dev/null 2>&1; then
  echo "malformed unrelated tag did not fail closed" >&2
  exit 1
fi

echo "Automatic chart version selection behavior passed"
