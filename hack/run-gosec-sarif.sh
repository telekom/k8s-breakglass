#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

gosec_bin="${GOSEC_BIN:-gosec}"
sarif_file="${GOSEC_SARIF_FILE:-gosec-results.sarif}"
log_file="${GOSEC_LOG_FILE:-gosec.log}"

run_scan() {
  rm -f -- "${sarif_file}"
  set +e
  "${gosec_bin}" \
    -exclude-generated \
    -exclude-dir=e2e \
    -exclude-dir=frontend/node_modules \
    -exclude=G101,G117,G302,G304,G704 \
    -fmt sarif \
    -out "${sarif_file}" \
    ./... 2>"${log_file}"
  scan_status=$?
  set -e
}

has_analyzer_error() {
  # gosec can return zero while skipping packages it could not load. Treat
  # analyzer and package-loading diagnostics as a failed security gate. Normal
  # progress messages ("Checking ...", "Import directory ...") do not match.
  grep -Eiq -- '(^|[[:space:]])(error running analyzer|error waiting for analyzers|rule error:|error building|type errors|no ssa|failed? to (load|build|analy[sz]e)|could not (load|import|analy[sz]e)|panic(:|[[:space:]])|fatal([[:space:]]|:)|skipping(:|[[:space:]]+(package|ssa))|cannot (load|import|analy[sz]e)|operation not permitted|undefined:)' "${log_file}"
}

valid_sarif() {
  # JSON syntax alone is not sufficient: `{}` would otherwise look like a
  # clean scan when the optional result traversal yields an empty list.
  jq -e '
    type == "object" and
    .version == "2.1.0" and
    (.runs | type == "array" and length > 0) and
    all(.runs[];
      type == "object" and
      (.tool.driver.name | type == "string" and length > 0) and
      (.results | type == "array")
    )
  ' "${sarif_file}" >/dev/null 2>&1
}

print_results() {
  jq -r '.runs[]?.results[]? | [.ruleId, .level, .message.text, .locations[0].physicalLocation.artifactLocation.uri, (.locations[0].physicalLocation.region.startLine // 0)] | @tsv' "${sarif_file}" >&2
}

run_scan
cat "${log_file}" >&2

if [[ ! -s "${sarif_file}" ]] || ! valid_sarif; then
  printf '%s\n' 'gosec did not produce a valid SARIF report; refusing a clean result' >&2
  [[ "${scan_status}" != 0 ]] && exit "${scan_status}"
  exit 1
fi

result_count="$(jq '[.runs[].results[]] | length' "${sarif_file}")"
if (( result_count > 0 )); then
  print_results
  exit 1
fi

if [[ "${scan_status}" != 0 ]]; then
  exit "${scan_status}"
fi
if has_analyzer_error; then
  printf '%s\n' 'gosec reported an analyzer/load error; refusing a clean result' >&2
  exit 1
fi
exit 0
