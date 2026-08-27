#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf -- "${fixture}"' EXIT HUP INT TERM

cat >"${fixture}/gosec" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
out=
while (($#)); do
  if [[ "$1" == -out ]]; then out=$2; shift 2; else shift; fi
done
case "${GOSEC_FIXTURE_MODE}" in
  clean) printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[]}]}' >"$out"; exit 0 ;;
  finding) printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[{"ruleId":"G999","level":"error","message":{"text":"fixture finding"}}]}]}' >"$out"; exit 1 ;;
  empty-object) printf '{}' >"$out"; exit 0 ;;
  missing-tool) printf '{"version":"2.1.0","runs":[{"results":[]}]}' >"$out"; exit 0 ;;
  analyzer-error) printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[]}]}' >"$out"; printf '%s\n' 'Error building the SSA representation of package fixture: type errors' >&2; exit 0 ;;
  skipped-ssa) printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[]}]}' >"$out"; printf '%s\n' 'package has type errors, skipping SSA' >&2; exit 0 ;;
  permission-error) printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[]}]}' >"$out"; printf '%s\n' 'operation not permitted while loading package' >&2; exit 0 ;;
  unknown-error) printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[]}]}' >"$out"; printf '%s\n' 'failed to load package fixture' >&2; exit 0 ;;
  analyzer-running) printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[]}]}' >"$out"; printf '%s\n' 'Error running analyzer G999: analyzer failed' >&2; exit 0 ;;
  analyzer-waiting) printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[]}]}' >"$out"; printf '%s\n' 'Error waiting for analyzers: analyzer failed' >&2; exit 0 ;;
  rule-error) printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[]}]}' >"$out"; printf '%s\n' 'Rule error: G999 => rule failed (fixture.go:1)' >&2; exit 0 ;;
  skipped-path) printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[]}]}' >"$out"; printf '%s\n' "Skipping: /workspace/fixture. Path doesn't exist." >&2; exit 0 ;;
  malformed) printf '%s\n' 'not SARIF' >"$out"; exit 0 ;;
esac
EOF
chmod +x "${fixture}/gosec"

run_case() {
  local mode="$1" expected="$2"
  set +e
  GOSEC_BIN="${fixture}/gosec" GOSEC_FIXTURE_MODE="${mode}" \
    GOSEC_SARIF_FILE="${fixture}/${mode}.sarif" GOSEC_LOG_FILE="${fixture}/${mode}.log" \
    "${root}/hack/run-gosec-sarif.sh" >/dev/null 2>&1
  local actual=$?
  set -e
  [[ "${actual}" == "${expected}" ]] || {
    printf 'gosec wrapper mode %s returned %s, expected %s\n' "${mode}" "${actual}" "${expected}" >&2
    exit 1
  }
}

run_case clean 0
run_case finding 1
run_case empty-object 1
run_case missing-tool 1
run_case analyzer-error 1
run_case skipped-ssa 1
run_case permission-error 1
run_case unknown-error 1
run_case analyzer-running 1
run_case analyzer-waiting 1
run_case rule-error 1
run_case skipped-path 1
run_case malformed 1
printf '%s\n' 'gosec SARIF wrapper behavior passed'
