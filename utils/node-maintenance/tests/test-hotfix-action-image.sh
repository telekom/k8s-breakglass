#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0
#
# Run hotfix-action from the real image in the mount-only file shape the
# controller uses (read-only root, only CHOWN/FOWNER/DAC_OVERRIDE, no
# privilege escalation) against a disposable host directory: plan, apply,
# idempotent re-apply and rollback of a sed patch, and the GNU sed sandbox.

set -Eeuo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)
image=${NODE_MAINTENANCE_TEST_IMAGE:-}
built=0
if [[ -z "$image" ]]; then
	image="node-maintenance-hotfix:$$"
	docker build --pull=false --tag "$image" "$root_dir" >/dev/null
	built=1
fi
work=$(mktemp -d)
cleanup() {
	# The container writes as root; remove its files from inside a container.
	docker run --rm --entrypoint /bin/rm -v "$work:/t" "$image" -rf /t/host >/dev/null 2>&1 || true
	rm -rf "$work"
	if [[ "$built" == 1 ]]; then
		docker image rm "$image" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

mkdir -p "$work/host/etc/ssh" "$work/host/var/lib/breakglass-hotfix"
printf 'Port 22\nPermitRootLogin yes\n' >"$work/host/etc/ssh/sshd_config"
before=$(sha256sum "$work/host/etc/ssh/sshd_config" | cut -d' ' -f1)
deadline=$(($(date +%s) + 600))

# run STAGE EXPRESSION [EXPECTED_JSON] prints the result JSON line.
run() {
	local stage=$1 expression=$2 expected=${3:-null}
	local request
	request=$(jq -cn --arg stage "$stage" --arg expr "$expression" --argjson expected "$expected" --argjson deadline "$deadline" \
		'{stage: $stage, hotfixID: "hf-image-test", deadlineUnix: $deadline, allowedPaths: ["/etc/ssh/"],
		  payload: {type: "node-file", file: {path: "/etc/ssh/sshd_config", mode: "sed", sedExpressions: [$expr]}}}
		 + (if $expected == null then {} else {expected: $expected} end)')
	docker run --rm --read-only --network none --user 0:0 \
		--cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
		--security-opt no-new-privileges --tmpfs /evidence:size=8m \
		-v "$work/host/etc/ssh:/host/etc/ssh" \
		-v "$work/host/var/lib/breakglass-hotfix:/host/var/lib/breakglass-hotfix" \
		-e BREAKGLASS_HOTFIX_REQUEST="$request" -e BREAKGLASS_TERMINATION_LOG=/evidence/termination-log \
		"$image" hotfix-action | tail -n 1
}

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

fix='s/^PermitRootLogin .*/PermitRootLogin no/'
plan=$(run plan "$fix")
[[ $(jq -r .result <<<"$plan") == planned && $(jq -r .action <<<"$plan") == apply ]] || fail "plan: $plan"
jq -r .diff <<<"$plan" | grep -q '^+PermitRootLogin no$' || fail "plan diff: $plan"
[[ $(sha256sum "$work/host/etc/ssh/sshd_config" | cut -d' ' -f1) == "$before" ]] || fail "plan changed the file"

expected=$(jq -c '{beforeSHA256, afterSHA256}' <<<"$plan")
applied=$(run apply "$fix" "$expected")
[[ $(jq -r .result <<<"$applied") == applied ]] || fail "apply: $applied"
grep -qx 'PermitRootLogin no' "$work/host/etc/ssh/sshd_config" || fail "file not patched"
[[ $(find "$work/host/etc/ssh" -mindepth 1 | wc -l) -eq 1 ]] || fail "temporary file left in the target directory"

again=$(run apply "$fix" "$expected")
[[ $(jq -r .result <<<"$again") == skipped ]] || fail "re-apply must skip: $again"

rolled=$(run rollback "$fix" "$expected")
[[ $(jq -r .result <<<"$rolled") == rolledBack ]] || fail "rollback: $rolled"
[[ $(sha256sum "$work/host/etc/ssh/sshd_config" | cut -d' ' -f1) == "$before" ]] || fail "rollback did not restore"

# GNU sed --sandbox rejects the w flag even if a request got past validation.
escape=$(run plan 's/Port/Port/w /host/etc/ssh/escaped' || true)
[[ $(jq -r .result <<<"$escape") == failed ]] || fail "sandbox: $escape"
[[ ! -e "$work/host/etc/ssh/escaped" ]] || fail "sed wrote a file"

printf 'hotfix-action image contract: PASS\n'
