#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: CC0-1.0

# Behavioral conformance tests for pr-gate-contract.sh. The tests use captured
# API-shaped fixtures and never inspect prompt text.
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
contract="$script_dir/pr-gate-contract.sh"
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT

fail() {
  printf 'test-pr-gate-contract: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
}

write_fixture() {
  local path="$1"
  shift
  printf '%s\n' "$1" >"$path"
}

valid_pr_url="https://github.com/telekom/k8s-breakglass/pull/1268"
parsed="$($contract parse-pr-url "$valid_pr_url")"
test "$parsed" = $'github.com\ttelekom/k8s-breakglass\t1268' || fail "valid HTTPS PR URL was not parsed"
expect_failure "$contract" parse-pr-url 'http://github.com/telekom/k8s-breakglass/pull/1268'
expect_failure "$contract" parse-pr-url 'https://token@github.com/telekom/k8s-breakglass/pull/1268'

write_fixture "$fixture_root/review-request.http" $'HTTP/2 201 Created\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\nContent-Type: application/json\r\n\r\n{}'
expect_failure "$contract" verify-review-freshness "$fixture_root/review-request.http" '2026-08-28T07:14:18.999Z'
"$contract" verify-review-freshness "$fixture_root/review-request.http" '2026-08-28T07:14:19.000Z'
write_fixture "$fixture_root/redirected-review-request.http" $'HTTP/2 302 Found\r\nDate: Fri, 28 Aug 2026 07:14:17 GMT\r\n\r\nHTTP/2 201 Created\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\n\r\n{}'
test "$("$contract" request-date "$fixture_root/redirected-review-request.http")" = 'Fri, 28 Aug 2026 07:14:18 GMT' ||
  fail "final HTTP response Date was not selected"

write_fixture "$fixture_root/effective-rules.json" '[
  {"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"test","integration_id":15368}]}},
  {"type":"pull_request","parameters":{"required_approving_review_count":1,"require_code_owner_review":true}},
  {"type":"required_workflows","parameters":{"workflows":[{"path":".github/workflows/test.yml","ref":"main"}]}},
  {"type":"required_deployments","parameters":{"required_deployment_environments":["staging"]}},
  {"type":"required_code_scanning","parameters":{"required_code_scanning_tools":[{"tool":"CodeQL"}]}},
  {"type":"required_signatures","parameters":{}}
]'
write_fixture "$fixture_root/protection.json" '{"required_status_checks":{"checks":[],"contexts":[]}}'
"$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/effective-rules.json" "$fixture_root/protection.json" "$fixture_root/inventory.json"
jq -e '.schema == 2 and (.requiredCheckRuns == [{"context":"test","appId":15368}]) and .mergeStateRequired' \
  "$fixture_root/inventory.json" >/dev/null || fail "supported rules were not inventoried"

write_fixture "$fixture_root/unknown-rule.json" '[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"test","integration_id":15368}]}},{"type":"commit_message_pattern","parameters":{"operator":"regex","pattern":".*"}}]'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/unknown-rule.json" "$fixture_root/protection.json" "$fixture_root/ignored.json"

write_fixture "$fixture_root/legacy-protection.json" '{"required_status_checks":{"checks":[],"contexts":["test"]}}'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/effective-rules.json" "$fixture_root/legacy-protection.json" "$fixture_root/ignored.json"

write_fixture "$fixture_root/repository.json" '{
  "id": 42,
  "full_name": "telekom/k8s-breakglass",
  "html_url": "https://github.com/telekom/k8s-breakglass",
  "url": "https://api.github.com/repos/telekom/k8s-breakglass"
}'
write_fixture "$fixture_root/identity.json" '{
  "data": {"repository": {"pullRequest": {
    "headRefName": "codex/network-debug",
    "headRefOid": "source-head",
    "baseRefName": "main",
    "baseRefOid": "base-head",
    "headRepository": {"nameWithOwner": "telekom/k8s-breakglass"},
    "baseRepository": {"nameWithOwner": "telekom/k8s-breakglass"},
    "potentialMergeCommit": {"oid": "synthetic-candidate"},
    "isDraft": false,
    "mergeable": "MERGEABLE",
    "mergeStateStatus": "CLEAN"
  }}}
}'
write_fixture "$fixture_root/runs.json" '[{
  "id": 111,
  "observedOid": "source-head",
  "head_sha": "source-head",
  "name": "test",
  "status": "completed",
  "conclusion": "success",
  "app": {"id": 15368, "owner": {"login": "github"}, "slug": "github-actions"},
  "check_suite": {"id": 222}
}]'
write_fixture "$fixture_root/suites.json" '[{
  "id": 222,
  "head_sha": "source-head",
  "app": {"id": 15368},
  "repository": {"id": 42, "full_name": "telekom/k8s-breakglass", "html_url": "https://github.com/telekom/k8s-breakglass", "url": "https://api.github.com/repos/telekom/k8s-breakglass"},
  "pull_requests": [{
    "head": {"sha": "source-head", "ref": "codex/network-debug", "repo": {"id": 42, "full_name": "telekom/k8s-breakglass", "html_url": "https://github.com/telekom/k8s-breakglass", "url": "https://api.github.com/repos/telekom/k8s-breakglass"}},
    "base": {"sha": "base-head", "ref": "main", "repo": {"id": 42, "full_name": "telekom/k8s-breakglass", "html_url": "https://github.com/telekom/k8s-breakglass", "url": "https://api.github.com/repos/telekom/k8s-breakglass"}}
  }]
}]'
write_fixture "$fixture_root/statuses.json" '[]'

# A passing check run on the exact source head is valid even though GitHub has
# also produced a distinct synthetic candidate for the same source/base pair.
"$contract" verify-checks "$fixture_root/identity.json" "$fixture_root/inventory.json" \
  "$fixture_root/repository.json" "$fixture_root/runs.json" "$fixture_root/suites.json" \
  "$fixture_root/statuses.json" "$fixture_root/verified.json"
jq -e '.verified == true and (.acceptedHeads | index("source-head")) != null and (.acceptedHeads | index("synthetic-candidate")) != null' \
  "$fixture_root/verified.json" >/dev/null || fail "exact source-head evidence was not accepted"

# The converse supported GitHub shape also passes: a check suite may be built
# for the synthetic candidate while its PR association still names the exact
# source/base pair.
jq '.[0].observedOid = "synthetic-candidate" | .[0].head_sha = "synthetic-candidate"' \
  "$fixture_root/runs.json" >"$fixture_root/candidate-runs.json"
jq '.[0].head_sha = "synthetic-candidate"' "$fixture_root/suites.json" >"$fixture_root/candidate-suites.json"
"$contract" verify-checks "$fixture_root/identity.json" "$fixture_root/inventory.json" \
  "$fixture_root/repository.json" "$fixture_root/candidate-runs.json" "$fixture_root/candidate-suites.json" \
  "$fixture_root/statuses.json" "$fixture_root/candidate-verified.json"
jq -e '.verified == true' "$fixture_root/candidate-verified.json" >/dev/null || fail "exact synthetic-candidate evidence was not accepted"

# The same context/App is not enough: a suite associated with a different
# source ref must not authorize the check.
jq '.[0].pull_requests[0].head.ref = "attacker-ref"' "$fixture_root/suites.json" >"$fixture_root/foreign-suite.json"
expect_failure "$contract" verify-checks "$fixture_root/identity.json" "$fixture_root/inventory.json" \
  "$fixture_root/repository.json" "$fixture_root/runs.json" "$fixture_root/foreign-suite.json" \
  "$fixture_root/statuses.json" "$fixture_root/ignored.json"

# A creator field on a legacy status cannot prove its GitHub App integration;
# any context collision therefore fails closed.
write_fixture "$fixture_root/colliding-statuses.json" '[{"context":"test","state":"success","creator":{"login":"github-actions[bot]","id":41898282}}]'
expect_failure "$contract" verify-checks "$fixture_root/identity.json" "$fixture_root/inventory.json" \
  "$fixture_root/repository.json" "$fixture_root/runs.json" "$fixture_root/suites.json" \
  "$fixture_root/colliding-statuses.json" "$fixture_root/ignored.json"

printf 'pr-gate-contract behavioral tests passed\n'
