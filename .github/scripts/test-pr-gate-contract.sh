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
expect_failure "$contract" parse-pr-url 'https://github.com:443/telekom/k8s-breakglass/pull/1268'

write_fixture "$fixture_root/review-request.http" $'HTTP/2 201 Created\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\nContent-Type: application/json\r\n\r\n{}'
expect_failure "$contract" verify-review-freshness "$fixture_root/review-request.http" '2026-08-28T07:14:18.999Z'
"$contract" verify-review-freshness "$fixture_root/review-request.http" '2026-08-28T07:14:19.000Z'
write_fixture "$fixture_root/redirected-review-request.http" $'HTTP/2 302 Found\r\nDate: Fri, 28 Aug 2026 07:14:17 GMT\r\n\r\nHTTP/2 201 Created\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\n\r\n{}'
test "$("$contract" request-date "$fixture_root/redirected-review-request.http")" = 'Fri, 28 Aug 2026 07:14:18 GMT' ||
  fail "final HTTP response Date was not selected"
write_fixture "$fixture_root/protection-200.http" $'HTTP/2 200 OK\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\n\r\n{"required_status_checks":{"checks":[],"contexts":[]}}'
"$contract" normalize-branch-protection-http "$fixture_root/protection-200.http" "$fixture_root/protection-200.json"
jq -e '.required_status_checks.checks == []' "$fixture_root/protection-200.json" >/dev/null ||
  fail "authenticated branch-protection 200 response was not normalized"
write_fixture "$fixture_root/protection-404.http" $'HTTP/2 404 Not Found\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\nContent-Type: application/json; charset=utf-8\r\nX-GitHub-Request-Id: AB12:CD34:EF56\r\n\r\n{"message":"Branch not protected","documentation_url":"https://docs.github.com/rest/branches/branch-protection#get-branch-protection","status":"404"}'
"$contract" normalize-branch-protection-http "$fixture_root/protection-404.http" "$fixture_root/protection-404.json"
jq -e '. == {}' "$fixture_root/protection-404.json" >/dev/null ||
  fail "authenticated branch-protection 404 did not become an empty policy"
write_fixture "$fixture_root/protection-404-empty.http" $'HTTP/2 404 Not Found\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\nContent-Type: application/json\r\nX-GitHub-Request-Id: AB12:CD34\r\n\r\n'
expect_failure "$contract" normalize-branch-protection-http "$fixture_root/protection-404-empty.http" "$fixture_root/ignored.json"
write_fixture "$fixture_root/protection-404-not-json.http" $'HTTP/2 404 Not Found\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\nContent-Type: application/json\r\nX-GitHub-Request-Id: AB12:CD34\r\n\r\nnot-json'
expect_failure "$contract" normalize-branch-protection-http "$fixture_root/protection-404-not-json.http" "$fixture_root/ignored.json"
write_fixture "$fixture_root/protection-404-malformed.http" $'HTTP/2 404 Not Found\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\nContent-Type: text/plain\r\nX-GitHub-Request-Id: AB12:CD34\r\n\r\n{"message":"Branch not protected","documentation_url":"https://docs.github.com/rest/branches/branch-protection#get-branch-protection","status":404}'
expect_failure "$contract" normalize-branch-protection-http "$fixture_root/protection-404-malformed.http" "$fixture_root/ignored.json"
write_fixture "$fixture_root/protection-404-missing-request-id.http" $'HTTP/2 404 Not Found\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\nContent-Type: application/json\r\n\r\n{"message":"Branch not protected","documentation_url":"https://docs.github.com/rest/branches/branch-protection#get-branch-protection","status":404}'
expect_failure "$contract" normalize-branch-protection-http "$fixture_root/protection-404-missing-request-id.http" "$fixture_root/ignored.json"
write_fixture "$fixture_root/protection-403.http" $'HTTP/2 403 Forbidden\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\n\r\n{"message":"forbidden"}'
expect_failure "$contract" normalize-branch-protection-http "$fixture_root/protection-403.http" "$fixture_root/ignored.json"

# A draft returned by gh must be the exact same direct-repository ref/OID pair
# that was verified before creation. A successful create response alone is not
# authorization to edit or ready an arbitrary PR.
write_fixture "$fixture_root/created-draft.json" '{"isDraft":true,"headRefName":"codex/network-debug","headRefOid":"source-head","headRepository":{"nameWithOwner":"telekom/k8s-breakglass"},"baseRefName":"main","baseRefOid":"base-head","baseRepository":{"nameWithOwner":"telekom/k8s-breakglass"}}'
"$contract" verify-created-draft "$fixture_root/created-draft.json" telekom/k8s-breakglass \
  codex/network-debug source-head main base-head
jq '.isDraft = false' "$fixture_root/created-draft.json" >"$fixture_root/not-a-draft.json"
expect_failure "$contract" verify-created-draft "$fixture_root/not-a-draft.json" telekom/k8s-breakglass \
  codex/network-debug source-head main base-head
jq '.headRefOid = "attacker-head"' "$fixture_root/created-draft.json" >"$fixture_root/wrong-draft-head.json"
expect_failure "$contract" verify-created-draft "$fixture_root/wrong-draft-head.json" telekom/k8s-breakglass \
  codex/network-debug source-head main base-head

# The evidence manifest covers every artifact, rather than just JSON. This
# catches a changed HTTP response (such as a different final status/header)
# between the verified and final snapshots.
mkdir -p "$fixture_root/manifest-snapshot"
write_fixture "$fixture_root/manifest-snapshot/identity.json" '{"b":2,"a":1}'
write_fixture "$fixture_root/manifest-snapshot/branch-protection.http" $'HTTP/2 200 OK\r\nDate: Fri, 28 Aug 2026 07:14:18 GMT\r\n\r\n{}'
"$contract" manifest-evidence "$fixture_root/manifest-snapshot" "$fixture_root/manifest-snapshot/gate.jsonl"
cp "$fixture_root/manifest-snapshot/gate.jsonl" "$fixture_root/first-manifest.jsonl"
write_fixture "$fixture_root/manifest-snapshot/branch-protection.http" $'HTTP/2 404 Not Found\r\nDate: Fri, 28 Aug 2026 07:14:19 GMT\r\n\r\n{}'
"$contract" manifest-evidence "$fixture_root/manifest-snapshot" "$fixture_root/manifest-snapshot/gate.jsonl"
cmp -s "$fixture_root/first-manifest.jsonl" "$fixture_root/manifest-snapshot/gate.jsonl" &&
  fail "changed HTTP evidence did not change the manifest"

write_fixture "$fixture_root/effective-rules.json" '[[
  {"type":"pull_request","parameters":{"dismiss_stale_reviews_on_push":true,"require_code_owner_review":true,"require_last_push_approval":false,"required_approving_review_count":1,"required_review_thread_resolution":true}},
  {"type":"workflows","parameters":{"workflows":[{"repository_id":42,"path":".github/workflows/test.yml","ref":"main","sha":"0123456789abcdef0123456789abcdef01234567"}]}}
], [
  {"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true,"required_status_checks":[{"context":"test","integration_id":15368}]}},
  {"type":"required_deployments","parameters":{"required_deployment_environments":["staging"]}},
  {"type":"code_scanning","parameters":{"code_scanning_tools":[{"tool":"CodeQL","alerts_threshold":"errors","security_alerts_threshold":"high_or_higher"}]}},
  {"type":"required_signatures"}
]]'
write_fixture "$fixture_root/protection.json" '{}'
"$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/effective-rules.json" "$fixture_root/protection.json" "$fixture_root/inventory.json"
jq -e '.schema == 2 and (.requiredCheckRuns == [{"context":"test","appId":15368}]) and .mergeStateRequired' \
  "$fixture_root/inventory.json" >/dev/null || fail "supported rules were not inventoried"

write_fixture "$fixture_root/unknown-rule.json" '[[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"test","integration_id":15368}]}}],[{"type":"commit_message_pattern","parameters":{"operator":"regex","pattern":".*"}}]]'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/unknown-rule.json" "$fixture_root/protection.json" "$fixture_root/ignored.json"

write_fixture "$fixture_root/legacy-protection.json" '{"required_status_checks":{"strict":true,"checks":[],"contexts":["test"]}}'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/effective-rules.json" "$fixture_root/legacy-protection.json" "$fixture_root/ignored.json"

# Known ruleset types must not be accepted with guessed/defaulted structures.
write_fixture "$fixture_root/malformed-status-rules.json" '[[{"type":"required_status_checks","parameters":{"required_status_checks":{"context":"test","integration_id":15368}}}]]'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/malformed-status-rules.json" "$fixture_root/protection.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/malformed-status-entry-rules.json" '[[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":42,"integration_id":"15368"}]}}]]'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/malformed-status-entry-rules.json" "$fixture_root/protection.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/malformed-workflow-rules.json" '[[{"type":"workflows","parameters":{"workflows":[{"path":".github/workflows/test.yml","ref":"main"}]}}]]'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/malformed-workflow-rules.json" "$fixture_root/protection.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/malformed-code-scanning-rules.json" '[[{"type":"code_scanning","parameters":{"required_code_scanning_tools":[{"tool":"CodeQL"}]}}]]'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/malformed-code-scanning-rules.json" "$fixture_root/protection.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/no-op-status-rules.json" '[[{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true,"required_status_checks":[]}}]]'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/no-op-status-rules.json" "$fixture_root/protection.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/malformed-pull-rules.json" '[[{"type":"pull_request","parameters":{"dismiss_stale_reviews_on_push":"true","require_code_owner_review":true,"require_last_push_approval":false,"required_approving_review_count":1,"required_review_thread_resolution":true}}]]'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/malformed-pull-rules.json" "$fixture_root/protection.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/malformed-status-flag-rules.json" '[[{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":"true","required_status_checks":[{"context":"test","integration_id":15368}]}}]]'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/malformed-status-flag-rules.json" "$fixture_root/protection.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/fractional-workflow-id-rules.json" '[[{"type":"workflows","parameters":{"workflows":[{"repository_id":42.5,"path":".github/workflows/test.yml","sha":"0123456789abcdef0123456789abcdef01234567"}]}}]]'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/fractional-workflow-id-rules.json" "$fixture_root/protection.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/malformed-code-threshold-rules.json" '[[{"type":"code_scanning","parameters":{"code_scanning_tools":[{"tool":"CodeQL","alerts_threshold":"warning","security_alerts_threshold":"high"}]}}]]'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/malformed-code-threshold-rules.json" "$fixture_root/protection.json" "$fixture_root/ignored.json"

# Empty ruleset pages are valid API output. A real classic branch-protection
# requirement must still produce a complete, usable inventory.
write_fixture "$fixture_root/empty-effective-rules.json" '[[], []]'
write_fixture "$fixture_root/classic-protection.json" '{
  "required_status_checks":{"strict":true,"checks":[{"context":"test","app_id":15368}],"contexts":["test"]},
  "required_pull_request_reviews":{"dismissal_restrictions":{"users":[],"teams":[],"apps":[]},"dismiss_stale_reviews":true,"require_code_owner_reviews":true,"required_approving_review_count":1,"require_last_push_approval":false,"bypass_pull_request_allowances":{"users":[],"teams":[],"apps":[]}},
  "required_conversation_resolution":{"enabled":true}
}'
"$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/empty-effective-rules.json" "$fixture_root/classic-protection.json" "$fixture_root/classic-inventory.json"
jq -e '.effectiveRules == [] and (.classicBranchProtectionRules | length) == 3 and
  .requiredCheckRuns == [{"context":"test","appId":15368}]' \
  "$fixture_root/classic-inventory.json" >/dev/null || fail "classic branch protection was not inventoried"

write_fixture "$fixture_root/empty-protection.json" '{}'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/empty-effective-rules.json" "$fixture_root/empty-protection.json" "$fixture_root/ignored.json"

write_fixture "$fixture_root/linear-history-protection.json" '{"required_status_checks":{"strict":true,"checks":[{"context":"test","app_id":15368}],"contexts":["test"]},"required_linear_history":{"enabled":true}}'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/empty-effective-rules.json" "$fixture_root/linear-history-protection.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/unsupported-classic-protection.json" '{"required_status_checks":{"strict":true,"checks":[{"context":"test","app_id":15368}],"contexts":["test"]},"block_creations":{"enabled":true}}'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/empty-effective-rules.json" "$fixture_root/unsupported-classic-protection.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/malformed-classic-protection.json" '{"required_status_checks":{"checks":"test","contexts":[]}}'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/empty-effective-rules.json" "$fixture_root/malformed-classic-protection.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/malformed-classic-status-policy.json" '{"required_status_checks":{"strict":"true","checks":[{"context":"test","app_id":15368}],"contexts":["test"]}}'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/empty-effective-rules.json" "$fixture_root/malformed-classic-status-policy.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/malformed-classic-review.json" '{"required_status_checks":{"strict":true,"checks":[{"context":"test","app_id":15368}],"contexts":["test"]},"required_pull_request_reviews":{"dismissal_restrictions":{"users":[],"teams":[],"apps":[]},"dismiss_stale_reviews":true,"require_code_owner_reviews":"true","required_approving_review_count":1,"require_last_push_approval":false}}'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/empty-effective-rules.json" "$fixture_root/malformed-classic-review.json" "$fixture_root/ignored.json"
write_fixture "$fixture_root/no-op-classic-status-policy.json" '{"required_status_checks":{"strict":true,"checks":[],"contexts":[]}}'
expect_failure "$contract" inventory-policy github.com telekom/k8s-breakglass main \
  "$fixture_root/empty-effective-rules.json" "$fixture_root/no-op-classic-status-policy.json" "$fixture_root/ignored.json"

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

"$contract" verify-checks "$fixture_root/identity.json" "$fixture_root/classic-inventory.json" \
  "$fixture_root/repository.json" "$fixture_root/runs.json" "$fixture_root/suites.json" \
  "$fixture_root/statuses.json" "$fixture_root/classic-verified.json"
jq -e '.verified == true' "$fixture_root/classic-verified.json" >/dev/null ||
  fail "classic branch-protection evidence was not accepted"

# The active workflow/deployment/code-scanning/signature rules are accepted
# only while GitHub's own exact-PR aggregate predicate remains policy-clean.
jq '.data.repository.pullRequest.mergeStateStatus = "BLOCKED"' "$fixture_root/identity.json" >"$fixture_root/blocked-identity.json"
expect_failure "$contract" verify-checks "$fixture_root/blocked-identity.json" "$fixture_root/inventory.json" \
  "$fixture_root/repository.json" "$fixture_root/runs.json" "$fixture_root/suites.json" \
  "$fixture_root/statuses.json" "$fixture_root/ignored.json"

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
