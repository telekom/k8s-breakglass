# GitHub PR Management

Use this prompt to create, update, review, rebase, and ready a pull request.
Treat a PR as approved only when one complete, current evidence snapshot passes.

## Repository, host, and command scope

- Pin every GitHub operation to the HTTPS host embedded in the actual PR URL.
  Do not rely on `GH_HOST`, the checked-out repository, a remote named
  `origin`, or a Git URL rewrite. The reference helper below rejects HTTP,
  credentials, ports, queries, fragments, malformed hosts, and malformed PR
  paths before a network request is made.
- Use `--repo HOST/BASE_OWNER/BASE_REPOSITORY` with every `gh pr` and `gh run`
  command. REST and GraphQL requests must use `gh api --hostname HOST`; their
  REST paths must include `repos/BASE_OWNER/BASE_REPOSITORY/...` and GraphQL
  calls must include explicit `owner` and `repo` variables.
- This task's user-directed policy permits direct same-repository branches
  only. Refuse fork pushes; do not repurpose this policy as a repository rule.
- Run the behavioural conformance suite before relying on a changed copy of
  this procedure:

  ```bash
  ./.github/scripts/test-pr-gate-contract.sh
  ```

  The prompt uses [`.github/scripts/pr-gate-contract.sh`](../scripts/pr-gate-contract.sh)
  as the executable reference for URL parsing, conservative review freshness,
  submitted-review selection, complete evidence manifests, draft binding,
  policy inventory, and exact check-suite evidence. It tests API-shaped
  fixtures, including a synthetic merge candidate that differs from the source
  head and attacker-controlled suite/status cases, and executes the draft
  lifecycle block with mocked GitHub/Git contracts. Unrelated prose is not
  treated as an executable requirement.

## Formal review requirements

Request a formal Copilot review; do not write an `@copilot review` comment.
The comment invokes the coding agent and is not a pull-request review request.

```bash
env GH_HOST="$github_host" gh pr edit "$pr" --repo "$hosted_repo" --add-reviewer @copilot
```

For the fail-closed gate below, use the equivalent REST reviewer request with
the configured bot login because its successful response carries GitHub's
server `Date` boundary. Do not substitute a local clock or a comment.

Use the known, repository-configured Copilot reviewer login, never a display
name or similarly named account. The selected review must be the newest review
from that exact login with all of these properties:

- `state` is `COMMENTED`, not dismissed;
- `submittedAt` is non-null and provably later than the recorded
  GitHub server-derived review-request completion time;
- `commit.oid` equals the captured PR `headRefOid`.

Copilot does not re-review every push unless the repository explicitly
configures it. A head or base OID change restarts the gate and requires a fresh
formal Copilot request/review. Its `COMMENTED` review is not a human approval:
the captured `reviewDecision` and the actual branch ruleset/code-owner policy
must independently show the current human and code-owner approvals required for
that same head/base pair. A review commit OID does not bind the base: the
request-completion timestamp is recorded after observing the pair, and final
identity comparison provides the required base binding.

## Fail-closed exact-head/base gate

Required CI may run directly on the source head, on GitHub's synthetic PR test
merge, or on a merge-queue candidate. Never accept a check merely because its
SHA equals the source head. It must be associated with the exact captured
head/base pair and the selected candidate, where applicable.

The gate is fail-closed. Start its shell with `set -euo pipefail`; any API,
pagination, validation, or comparison failure means **restart**, not ready or
merge. Capture and retain all raw JSON in a private temporary directory for the
gate run; do not use a green result from an earlier run.

```bash
set -euo pipefail

fail() { printf '%s\n' "$*" >&2; exit 1; }

# Derive both target repository and number from the actual PR URL.
# Supply the exact browser/API URL rather than a host placeholder. The parser
# pins host/repository/number before any `gh` or Git network operation.
pr_url="https://github.com/BASE_OWNER/BASE_REPOSITORY/pull/PR_NUMBER"
contract="./.github/scripts/pr-gate-contract.sh"
test -x "$contract" || fail "missing executable PR-gate contract helper"
IFS=$'\t' read -r github_host base_repo pr <<EOF
$($contract parse-pr-url "$pr_url")
EOF
hosted_repo="$github_host/$base_repo"
gh_api() { env GH_HOST="$github_host" gh api --hostname "$github_host" "$@"; }
gh_pr() { env GH_HOST="$github_host" gh pr "$@"; }
gh auth status --hostname "$github_host" >/dev/null ||
  fail "no authenticated gh session for the pinned GitHub host"
case "$base_repo" in */*) ;; *) fail "invalid PR repository";; esac
case "$pr" in ''|*[!0-9]*) fail "invalid PR number";; esac

gate_root="$(mktemp -d)"
trap 'rm -rf "$gate_root"' EXIT
observed="$gate_root/observed.json"
copilot_reviewer_login="${copilot_reviewer_login-}"
: "${copilot_reviewer_login:?set the repository-configured Copilot reviewer login}"
case "$copilot_reviewer_login" in
  *'[bot]') copilot_login_core="${copilot_reviewer_login%?????}";;
  *) copilot_login_core="$copilot_reviewer_login";;
esac
case "$copilot_login_core" in ''|*[!A-Za-z0-9-]*|-*|*-)
  fail "invalid Copilot reviewer login";;
esac

capture_identity() {
  # shellcheck disable=SC2016
  # GraphQL variables must reach gh unchanged.
  gh_api graphql -f query='
    query($owner:String!, $repo:String!, $pr:Int!) {
      repository(owner:$owner, name:$repo) {
        pullRequest(number:$pr) {
          headRefName headRefOid baseRefName baseRefOid isDraft mergeable mergeStateStatus
          headRepository { id nameWithOwner }
          baseRepository { id nameWithOwner }
          reviewDecision
          potentialMergeCommit { oid }
          mergeQueueEntry { id }
        }
      }
    }
  ' -f owner="${base_repo%/*}" -f repo="${base_repo#*/}" -F pr="$pr"
}

# `reviewDecision`, mergeability, and merge-state legitimately change while CI
# and reviews complete. Bind only immutable source/base/candidate identity
# across the review request; validate mutable policy state in each snapshot.
identity_binding() {
  jq -S '
    .data.repository.pullRequest |
    {headRefName, headRefOid, baseRefName, baseRefOid,
     headRepository: {id: .headRepository.id, nameWithOwner: .headRepository.nameWithOwner},
     baseRepository: {id: .baseRepository.id, nameWithOwner: .baseRepository.nameWithOwner},
     potentialMergeCommit: (.potentialMergeCommit | if . == null then null else {oid} end),
     mergeQueueEntry: (.mergeQueueEntry | if . == null then null else {id} end)}
  ' "$1"
}

request_formal_review() {
  review_request_http="$gate_root/review-request.http"
  # REST is the formal reviewer API equivalent of `gh pr edit --add-reviewer`.
  # --include preserves the GitHub server Date header with the successful POST.
  gh_api --include -X POST "repos/$base_repo/pulls/$pr/requested_reviewers" \
    -f "reviewers[]=$copilot_reviewer_login" >"$review_request_http"
  request_server_date="$($contract request-date "$review_request_http")" ||
    fail "ambiguous GitHub review-request Date"
  request_server_ns="$($contract request-date-to-ns "$review_request_http")" ||
    fail "ambiguous GitHub review-request Date"
  case "$request_server_ns" in ''|*[!0-9]*)
    fail "invalid GitHub review-request boundary";;
  esac
  jq -n --arg serverDate "$request_server_date" \
    --arg requestServerNanoseconds "$request_server_ns" \
    '{serverDate: $serverDate, requestServerNanoseconds: $requestServerNanoseconds}' \
    >"$gate_root/review-request.json"
}

# Observe the source/base before requesting a fresh review.
capture_identity >"$observed"
jq -e '((.errors // []) | length) == 0 and .data != null and
       .data.repository.pullRequest != null and
       .data.repository.pullRequest.headRefOid and
       .data.repository.pullRequest.baseRefOid and
       .data.repository.pullRequest.headRepository.nameWithOwner and
       .data.repository.pullRequest.baseRepository.nameWithOwner' \
  "$observed" >/dev/null || fail "incomplete PR identity"
identity_binding "$observed" >"$gate_root/observed-identity-binding.json"
base_ref="$(jq -r '.data.repository.pullRequest.baseRefName' "$observed")"
```

Do not infer a merge-queue commit SHA from `mergeQueueEntry.id`. This workflow
does not have a reliable API binding from that ID to the merge-group commit, so
it stops rather than overclaims merge-queue evidence:

```bash
jq -e '.data.repository.pullRequest.mergeQueueEntry == null' \
  "$observed" >/dev/null || \
  fail "merge queue active: no reliable candidate SHA; do not ready or merge"

head_oid="$(jq -r '.data.repository.pullRequest.headRefOid' "$observed")"
base_oid="$(jq -r '.data.repository.pullRequest.baseRefOid' "$observed")"
candidate_oid="$(jq -r \
  '.data.repository.pullRequest.potentialMergeCommit.oid // .data.repository.pullRequest.headRefOid' \
  "$observed")"
```

Once the requested review and required CI are complete, take the first complete
evidence capture in `$gate_root/verified`. Its immutable source/base/candidate
identity projection must byte-match the observed projection before use;
approval/merge-state fields are deliberately re-read because they are expected
to change while the review completes. Validate the evidence, then repeat the
*same* collection into `$gate_root/final` immediately before ready/merge. Both
captures must use the same filenames and include a fresh `identity.json`.

### Evidence that one gate snapshot must contain

Capture every page of each connection. A complete snapshot contains:

| Evidence | Required fields and decision |
| --- | --- |
| PR identity | pinned HTTPS host; `headRefOid`, `baseRefOid`, source/base repository and refs, test-merge SHA, `reviewDecision`, `mergeable`, `mergeStateStatus`, draft state |
| Formal reviews | review ID, configured reviewer `author.login`, state, `submittedAt`, `commit.oid`; select the newest configured Copilot review no earlier than the first whole second after GitHub's server `Date` boundary |
| Human approval | `reviewDecision == APPROVED`, zero unresolved threads, and the current `mergeable == MERGEABLE` / `mergeStateStatus == CLEAN` server predicate for the pair; Copilot does not satisfy this row |
| Threads and comments | every thread ID/resolution/outdated state and every comment ID, minimized state/reason, author, path, line, and timestamp |
| Checks | complete expected inventory, result, `head_sha`, check-suite ID, and `CheckRun.app.owner.login`, `CheckRun.app.slug`, and `CheckRun.app.id` |
| Legacy statuses | every context, state, target URL, and `creator.login`/`creator.id`; reject a status that attempts to satisfy a required context because GitHub rules do not bind its creator |
| Check suites | suite ID, `head_sha`, app/provider identity, suite repository identity/HTTPS URL, and each associated PR's source/base repository identity, refs, and SHAs |

Fetch GitHub's effective branch rules and branch-protection object into every
snapshot. Inventory **every active rule type and its parameters**, not only
status checks. The contract validates App-bound required checks directly and
uses GitHub's exact-PR final `MERGEABLE`/`CLEAN` predicate in addition for
active `pull_request`, `required_signatures`, `workflows`,
`required_deployments`, and `code_scanning` rules. The effective ruleset pages
and classic branch-protection requirements form one inventory: a repository
with no rulesets but an App-bound classic required check is supported, while a
repository with neither fails closed. Classic `required_linear_history` and
every other enabled classic control without an explicit verifier are synthesized
into that inventory and fail closed with their exact payload; malformed known
ruleset/classic schemas fail before validation. A merge queue,
linear-history rule, or any unrecognised active type fails closed with the
server-provided type/parameters in the error: extend the verifier for that
type, or remove/replace the rule before using this ready/merge gate. It never
silently ignores a rule, accepts `NEUTRAL`/`SKIPPED`, or accepts a legacy
required status, whose `creator` cannot prove a GitHub App integration.

The policy verifier accepts only the documented payloads it can enforce:
`pull_request` requires every review boolean and an integer approval count;
`required_status_checks` requires its strict flag and a nonempty list of
positive App integration IDs; workflow entries require an integer
`repository_id`, path, and immutable SHA; and code-scanning thresholds must be
GitHub's documented enum values. Classic status policy requires `strict`,
`contexts`, and `checks`; classic reviews require their dismissal, code-owner,
stale-review, last-push, and approval fields with their documented types. An
empty active status-check list, a malformed payload, or an enabled control the
contract does not model is fatal. A classic context that is also present in an
exact App-bound classic check is permitted; any unbound context is rejected.

The following commands provide the raw, paginated review/thread/check material.
Save each response under the gate directory and normalize it with sorted JSON
before comparing snapshots.

```bash
require_graphql_pages() {
  jq -e 'type == "array" and length > 0 and
    all(.[]; ((.errors // []) | length) == 0 and .data != null)' "$1" >/dev/null ||
    fail "GraphQL error, missing data, or incomplete page collection: $1"
}

collect_reviews_and_threads() {
  gate_dir="$1"
  # Formal reviews; evaluate the exact-login/latest/COMMENTED/time/head predicate.
  # shellcheck disable=SC2016
  # GraphQL variables must reach gh unchanged.
  gh_api graphql --paginate --slurp -f query='
  query($owner:String!, $repo:String!, $pr:Int!, $endCursor:String) {
    repository(owner:$owner, name:$repo) {
      pullRequest(number:$pr) {
        reviews(first:100, after:$endCursor) {
          pageInfo { hasNextPage endCursor }
          nodes { id author { login } state submittedAt commit { oid } }
        }
      }
    }
  }
' -f owner="${base_repo%/*}" -f repo="${base_repo#*/}" -F pr="$pr" \
  -F endCursor=null >"$gate_dir/reviews.json"
require_graphql_pages "$gate_dir/reviews.json"
jq -e 'all(.[]; .data.repository.pullRequest != null and
  .data.repository.pullRequest.reviews.pageInfo != null) and
  .[-1].data.repository.pullRequest.reviews.pageInfo.hasNextPage == false' \
  "$gate_dir/reviews.json" >/dev/null || fail "missing review pageInfo"

"$contract" select-copilot-review "$gate_dir/reviews.json" \
  "$copilot_reviewer_login" "$head_oid" "$gate_dir/copilot-review.json" ||
  fail "missing current, submitted formal Copilot review"

review_submitted_at="$(jq -r .submittedAt "$gate_dir/copilot-review.json")"
$contract verify-review-freshness "$gate_root/review-request.http" "$review_submitted_at" ||
  fail "formal Copilot review is not provably after GitHub request completion"

  # All review threads. Paginate every returned thread's comments separately.
  # shellcheck disable=SC2016
  # GraphQL variables must reach gh unchanged.
  gh_api graphql --paginate --slurp -f query='
  query($owner:String!, $repo:String!, $pr:Int!, $endCursor:String) {
    repository(owner:$owner, name:$repo) {
      pullRequest(number:$pr) {
        reviewThreads(first:100, after:$endCursor) {
          pageInfo { hasNextPage endCursor }
          nodes {
            id isResolved isOutdated
            comments(first:100) {
              pageInfo { hasNextPage endCursor }
              nodes { id body author { login } path line createdAt isMinimized minimizedReason }
            }
          }
        }
      }
    }
  }
' -f owner="${base_repo%/*}" -f repo="${base_repo#*/}" -F pr="$pr" \
  -F endCursor=null >"$gate_dir/threads.json"
require_graphql_pages "$gate_dir/threads.json"
jq -e 'all(.[]; .data.repository.pullRequest != null and
  .data.repository.pullRequest.reviewThreads.pageInfo != null) and
  .[-1].data.repository.pullRequest.reviewThreads.pageInfo.hasNextPage == false' \
  "$gate_dir/threads.json" >/dev/null || fail "missing thread pageInfo"

thread_number=0
  jq -r '.[].data.repository.pullRequest.reviewThreads.nodes[].id' \
  "$gate_dir/threads.json" | while IFS= read -r thread_id; do
    thread_number=$((thread_number + 1))
    # shellcheck disable=SC2016
    # GraphQL variables must reach gh unchanged.
    gh_api graphql --paginate --slurp -f query='
      query($thread:ID!, $endCursor:String) {
        node(id:$thread) {
          ... on PullRequestReviewThread {
            comments(first:100, after:$endCursor) {
              pageInfo { hasNextPage endCursor }
              nodes { id body author { login } path line createdAt isMinimized minimizedReason }
            }
          }
        }
      }
    ' -F thread="$thread_id" -F endCursor=null \
      >"$gate_dir/thread-comments-$thread_number.json"
    require_graphql_pages "$gate_dir/thread-comments-$thread_number.json"
    jq -e 'all(.[]; .data.node != null and .data.node.comments.pageInfo != null) and
      .[-1].data.node.comments.pageInfo.hasNextPage == false' \
      "$gate_dir/thread-comments-$thread_number.json" >/dev/null ||
      fail "missing comment pageInfo"
  done
}
```

Every unresolved thread blocks this task's gate, including an outdated thread.
Minimized is not resolved. A future ruleset exception must be machine-validated
with its exact rule source; a “documented disposition” is never an exception.
Resolve a thread only after its fix is present in the current head.

```bash
collect_ci_and_statuses() {
  gate_dir="$1"
  # REST carries check runs, suites, and legacy statuses. `filter=latest`
  # avoids treating a superseded failed rerun as the current required run.
  oid_list=("$head_oid")
  test "$candidate_oid" = "$head_oid" || oid_list+=("$candidate_oid")
  for oid in "${oid_list[@]}"; do
    gh_api --paginate --slurp \
      "repos/$base_repo/commits/$oid/check-runs?per_page=100&filter=latest" \
      >"$gate_dir/check-runs-$oid.json"
    gh_api --paginate --slurp \
      "repos/$base_repo/commits/$oid/check-suites?per_page=100" \
      >"$gate_dir/check-suites-$oid.json"
    gh_api --paginate --slurp \
      "repos/$base_repo/commits/$oid/status?per_page=100" \
      >"$gate_dir/status-contexts-$oid.json"

    # A successful HTTP response is not enough: reject incomplete, malformed,
    # or unexpectedly unpaginated payloads before direct inventory validation.
    jq -e 'type == "array" and length > 0 and
      all(.[]; (.check_runs | type) == "array")' \
      "$gate_dir/check-runs-$oid.json" >/dev/null ||
      fail "invalid check-run response for $oid"
    jq -e 'type == "array" and length > 0 and
      all(.[]; (.check_suites | type) == "array")' \
      "$gate_dir/check-suites-$oid.json" >/dev/null ||
      fail "invalid check-suite response for $oid"
    jq -e 'type == "array" and length > 0 and
      all(.[]; (.state | type) == "string" and (.statuses | type) == "array")' \
      "$gate_dir/status-contexts-$oid.json" >/dev/null ||
      fail "invalid legacy-status response for $oid"

    jq --arg oid "$oid" '[.[] | .check_runs[]? | . + {observedOid: $oid}]' \
      "$gate_dir/check-runs-$oid.json" >"$gate_dir/runs-$oid.json"
    jq --arg oid "$oid" '[.[] | .check_suites[]? | . + {observedOid: $oid}]' \
      "$gate_dir/check-suites-$oid.json" >"$gate_dir/suites-$oid.json"
    jq --arg oid "$oid" '[.[] | .statuses[]? | . + {observedOid: $oid}]' \
      "$gate_dir/status-contexts-$oid.json" >"$gate_dir/statuses-$oid.json"
  done

  jq -s 'add' "$gate_dir"/runs-*.json >"$gate_dir/check-runs-normalized.json"
  jq -s 'add' "$gate_dir"/suites-*.json >"$gate_dir/check-suites-normalized.json"
  jq -s 'add' "$gate_dir"/statuses-*.json >"$gate_dir/status-contexts-normalized.json"
}
```

The expected inventory is built from GitHub's effective rules for the captured
base ref and its branch-protection object—not from a caller file. The collector
refuses an empty inventory, a legacy required context
without an integration ID, a duplicate context, or an unsupported provider
binding. GitHub does not bind a legacy status context to a creator; therefore a
legacy status can never satisfy a required check in this gate. This is a
deliberate fail-closed limitation, not a reason to treat an unknown context as
green.

```bash
collect_policy_inventory() {
  gate_dir="$1"
  # Branch refs are one REST path segment. Encode every byte outside the URI
  # unreserved set so refs such as `feature/review` cannot change the endpoint
  # path (and spaces, `%`, or `+` cannot be interpreted by a proxy).
  encoded_base_ref="$(jq -nr --arg ref "$base_ref" '$ref | @uri')"
  test -n "$encoded_base_ref" || fail "could not URL-encode base ref"
  gh_api --paginate --slurp \
    "repos/$base_repo/rules/branches/$encoded_base_ref" \
    >"$gate_dir/effective-rules.json"
  # `--slurp` yields an array of arrays, one per pagination page. Empty
  # ruleset pages are valid; the contract combines them with classic branch
  # protection and rejects only when both sources are genuinely no-op.
  jq -e 'type == "array" and all(.[]; type == "array")' \
    "$gate_dir/effective-rules.json" >/dev/null ||
    fail "missing or malformed effective branch rules"

  # Capture the authenticated HTTP response even when `gh` returns non-zero.
  # The contract accepts only a final HTTP 200 object or an authenticated 404
  # (which conclusively means this branch has no classic protection). A 404 is
  # accepted only with one valid Date, a GitHub request ID, JSON content type,
  # and GitHub's `Branch not protected` JSON error/documentation URL/status;
  # empty, non-JSON, malformed, 401/403, 5xx, and every other response remain
  # fatal.
  protection_http="$gate_dir/branch-protection.http"
  if gh_api --include "repos/$base_repo/branches/$encoded_base_ref/protection" \
    >"$protection_http"; then
    :
  else
    : # normalize-branch-protection-http validates the final HTTP status below.
  fi
  "$contract" normalize-branch-protection-http "$protection_http" \
    "$gate_dir/branch-protection.json"
  jq -e 'type == "object"' "$gate_dir/branch-protection.json" >/dev/null ||
    fail "malformed branch protection"

  "$contract" inventory-policy "$github_host" "$base_repo" "$base_ref" \
    "$gate_dir/effective-rules.json" "$gate_dir/branch-protection.json" \
    "$gate_dir/expected-inventory.json"
}

validate_exact_inventory() {
  snapshot="$1"
  "$contract" verify-checks "$snapshot/identity.json" \
    "$snapshot/expected-inventory.json" "$snapshot/repository.json" \
    "$snapshot/check-runs-normalized.json" "$snapshot/check-suites-normalized.json" \
    "$snapshot/status-contexts-normalized.json" "$snapshot/check-verdict.json"
}

# Bind policy to the observed base before asking for review. A policy change
# later invalidates the request and the two snapshots must remain byte-identical.
mkdir -p "$gate_root/observed-policy"
collect_policy_inventory "$gate_root/observed-policy"
request_formal_review

capture_snapshot() {
  gate_dir="$1"
  mkdir -p "$gate_dir"
  cp "$gate_root/review-request.json" "$gate_dir/review-request.json"
  cp "$gate_root/review-request.http" "$gate_dir/review-request.http"
  capture_identity >"$gate_dir/identity.json"
  jq -e '((.errors // []) | length) == 0 and
    .data != null and .data.repository.pullRequest != null and
    .data.repository.pullRequest.headRefOid != null and
    .data.repository.pullRequest.baseRefOid != null and
    .data.repository.pullRequest.headRepository.nameWithOwner != null and
    .data.repository.pullRequest.baseRepository.nameWithOwner != null and
    .data.repository.pullRequest.mergeQueueEntry == null' \
    "$gate_dir/identity.json" >/dev/null || fail "invalid final PR identity"
  identity_binding "$gate_dir/identity.json" >"$gate_dir/identity-binding.json"
  cmp -s "$gate_root/observed-identity-binding.json" "$gate_dir/identity-binding.json" ||
    fail "PR head/base/candidate changed; restart and re-request Copilot"
  head_oid="$(jq -r '.data.repository.pullRequest.headRefOid' "$gate_dir/identity.json")"
  base_oid="$(jq -r '.data.repository.pullRequest.baseRefOid' "$gate_dir/identity.json")"
  candidate_oid="$(jq -r \
    '.data.repository.pullRequest.potentialMergeCommit.oid // .data.repository.pullRequest.headRefOid' \
    "$gate_dir/identity.json")"
  gh_api "repos/$base_repo" >"$gate_dir/repository.json"
  jq -e --arg host "$github_host" --arg repo "$base_repo" '
    (.id | type) == "number" and .full_name == $repo and
    .html_url == ("https://" + $host + "/" + $repo) and (.url | type) == "string"
  ' "$gate_dir/repository.json" >/dev/null ||
    fail "repository capture is not pinned to the HTTPS GitHub host"
  collect_policy_inventory "$gate_dir"
  cmp -s "$gate_root/observed-policy/expected-inventory.json" \
    "$gate_dir/expected-inventory.json" ||
    fail "effective rules/check/provider inventory changed; restart and re-request Copilot"
  collect_reviews_and_threads "$gate_dir"
  collect_ci_and_statuses "$gate_dir"
}

validate_snapshot() {
  snapshot="$1"
  for evidence in "$snapshot"/*.json; do
    "$contract" validate-json "$evidence"
  done
  jq -e '.data.repository.pullRequest.reviewDecision == "APPROVED"' \
    "$snapshot/identity.json" >/dev/null || fail "missing current human approval"
  jq -e '[.[] | .data.repository.pullRequest.reviewThreads.nodes[] |
    select(.isResolved != true)] | length == 0' \
    "$snapshot/threads.json" >/dev/null || fail "unresolved review thread"
  validate_exact_inventory "$snapshot"
}

# First complete collection and validation, followed by the complete final rerun.
capture_snapshot "$gate_root/verified"
validate_snapshot "$gate_root/verified"
capture_snapshot "$gate_root/final"
validate_snapshot "$gate_root/final"
```

Before marking ready or merging, create a normalized, sorted manifest from all
the files above, including the server-fetched effective rules and protection.
Validate the formal-Copilot predicate, human/code-owner approval, zero unpermitted
unresolved threads, and every expected check/provider/suite association. Then
capture the **entire** evidence set again and compare the two manifests:

```bash
manifest_snapshot() {
  snapshot="$1"
  # JSON files are canonicalized with duplicate object keys rejected. HTTP
  # responses are parsed and validated,
  # then represented by final status, stable headers, and canonical body;
  # GitHub's volatile Date/request-ID/rate-limit transport metadata is
  # deliberately excluded only after validation. Repeated stable-header order
  # is preserved. Other artifacts use SHA-256.
  # The helper omits only the manifest it is writing.
  "$contract" manifest-evidence "$snapshot" "$snapshot/gate.jsonl"
}

# Both snapshots were collected and validated above. Reject any changed raw or
# normalized evidence immediately before the ready mutation.
manifest_snapshot "$gate_root/verified"
manifest_snapshot "$gate_root/final"
cmp -s "$gate_root/verified/gate.jsonl" "$gate_root/final/gate.jsonl" || \
  fail "gate evidence changed; restart from identity and request a new review"

# This is the only mutation in this block. Do not launch a browser or inspect
# additional mutable state between the final manifest comparison and ready.
gh_pr ready "$pr" --repo "$hosted_repo"
```

The final capture must still have the observed head/base pair. A changed head or
base invalidates Copilot, human approval, checks, and threads; restart rather
than carrying any evidence forward.

## Rebasing a same-repository PR safely

Use signed child commits where possible. Rewrite only an authorized direct PR
branch, and only after deriving its live source and base from the PR URL.

```bash
set -euo pipefail

pr_data="$(gh_pr view "$pr" --repo "$hosted_repo" \
  --json baseRefName,baseRefOid,headRefName,headRefOid,headRepository)"
pr_identity="$(jq -S -c . <<<"$pr_data")"
base_ref="$(jq -r .baseRefName <<<"$pr_data")"
base_oid="$(jq -r .baseRefOid <<<"$pr_data")"
head_ref="$(jq -r .headRefName <<<"$pr_data")"
head_oid="$(jq -r .headRefOid <<<"$pr_data")"
head_repo="$(jq -r .headRepository.nameWithOwner <<<"$pr_data")"
test "$head_repo" = "$base_repo" || { echo "refusing fork push" >&2; exit 1; }

# A URL rewrite can make the configured spelling differ from the actual target.
# Reject it rather than attempting to reason about insteadOf/pushInsteadOf.
if git config --get-regexp '^url\..*\.(insteadOf|pushInsteadOf)$' >/dev/null; then
  echo "URL rewrite configuration is present; refusing to select a push endpoint" >&2
  exit 1
fi

# A selected remote must have exactly one HTTPS fetch/push URL whose host and
# repository exactly match the live same-repository PR source. Do not inspect
# arbitrary SSH/custom URLs through `gh repo view`: that would make endpoint
# verification depend on a second, unpinned host selection.
expected_https_remote="https://$github_host/$head_repo.git"
push_remote=""
for candidate in $(git remote); do
  fetch_url="$(git remote get-url "$candidate")"
  push_urls="$(git remote get-url --push --all "$candidate")"
  push_count="$(printf '%s\n' "$push_urls" | awk 'NF { count++ } END { print count + 0 }')"
  if test "$push_count" != 1; then
    printf 'rejecting remote %s: expected exactly one push URL\n' "$candidate" >&2
    continue
  fi
  push_url="$(printf '%s\n' "$push_urls" | sed -n '1p')"
  if test "$fetch_url" != "$expected_https_remote" || test "$push_url" != "$expected_https_remote"; then
    printf 'rejecting remote %s: endpoint is not the pinned HTTPS PR source\n' "$candidate" >&2
    continue
  fi
  test -z "$push_remote" || { echo "ambiguous verified remotes" >&2; exit 1; }
  push_remote="$candidate"
done
test -n "$push_remote" || { echo "no single verified push target" >&2; exit 1; }

git fetch "$push_remote" \
  "refs/heads/$base_ref:refs/remotes/$push_remote/$base_ref" \
  "refs/heads/$head_ref:refs/remotes/$push_remote/$head_ref"
test "$(git rev-parse "$push_remote/$base_ref")" = "$base_oid"
remote_head="$(git rev-parse "$push_remote/$head_ref")"
test "$remote_head" = "$head_oid"
test "$(git rev-parse HEAD)" = "$head_oid" || { echo "stale checkout" >&2; exit 1; }
test "$(git branch --show-current)" = "$head_ref"
test -z "$(git status --porcelain)" || { echo "dirty worktree" >&2; exit 1; }

if ! git rebase --gpg-sign "$push_remote/$base_ref"; then
  echo "rebase stopped; do not push" >&2
  git status --short
  exit 1
fi
git rebase --show-current-patch >/dev/null 2>&1 && { echo "rebase remains" >&2; exit 1; }
test -z "$(git status --porcelain)" || { echo "dirty after rebase" >&2; exit 1; }
test "$(git merge-base HEAD "$push_remote/$base_ref")" = \
  "$(git rev-parse "$push_remote/$base_ref")"
rebased_head="$(git rev-parse HEAD)"
git cat-file -e "$rebased_head^{commit}"

signature_statuses="$(git log --format='%G?' "$push_remote/$base_ref..HEAD")"
printf '%s\n' "$signature_statuses"
if printf '%s\n' "$signature_statuses" | grep -Eq '[^G]'; then
  echo "rewritten commits are not all validly signed" >&2
  exit 1
fi

# Re-read live PR metadata. Pin the immutable, verified post-rebase OID; any
# source/base movement or local mutation means start over. The lease protects
# the small interval between this read and the push.
live_pr_data="$(gh_pr view "$pr" --repo "$hosted_repo" \
  --json baseRefName,baseRefOid,headRefName,headRefOid,headRepository)"
test "$(jq -S -c . <<<"$live_pr_data")" = "$pr_identity" || {
  echo "PR moved while rebasing; do not push" >&2; exit 1;
}
test "$(git rev-parse HEAD)" = "$rebased_head" || {
  echo "post-rebase OID changed after verification; do not push" >&2; exit 1;
}
git push --force-with-lease="refs/heads/$head_ref:$remote_head" \
  "$push_remote" "$rebased_head:refs/heads/$head_ref"
test "$(git ls-remote "$expected_https_remote" "refs/heads/$head_ref" | awk '{print $1}')" = "$rebased_head" || {
  echo "remote did not retain the verified post-rebase OID" >&2; exit 1;
}
test "$(gh_pr view "$pr" --repo "$hosted_repo" --json headRefOid --jq .headRefOid)" = "$rebased_head" || {
  echo "GitHub PR source is not the verified post-rebase OID" >&2; exit 1;
}
```

If a rebase stops, resolve and stage only the named conflict paths, then
continue; otherwise run `git rebase --abort`. After either path, rerun every
post-rebase guard before a push. Never use broad `--force`, reset-based squash,
unsigned amend, or `git add -A`.

## Stacked child PRs

Discover the open stack from actual base/head branch relationships; do not rely
on PR number order or a manually remembered stack. Rebase in dependency order
from parent to child, then run a fresh review and complete gate for **each** PR.

```bash
# `gh pr list --limit 100` is not a stack inventory. GraphQL pagination captures
# every open PR and includes the source repository needed to reject forks.
stack_root_base=STACK_ROOT_BASE_REF
git check-ref-format --branch "$stack_root_base" >/dev/null
# shellcheck disable=SC2016
# GraphQL variables must reach gh unchanged.
gh_api graphql --paginate --slurp -f query='
  query($owner:String!, $repo:String!, $endCursor:String) {
    repository(owner:$owner, name:$repo) {
      pullRequests(first:100, states:OPEN, after:$endCursor) {
        pageInfo { hasNextPage endCursor }
        nodes { number url headRefName baseRefName headRepository { nameWithOwner } }
      }
    }
  }
' -f owner="${base_repo%/*}" -f repo="${base_repo#*/}" -F endCursor=null \
  >"$gate_root/open-pr-pages.json"
require_graphql_pages "$gate_root/open-pr-pages.json"
jq -e 'all(.[]; .data.repository.pullRequests.pageInfo != null and
  .data.repository.pullRequests.nodes != null) and
  .[-1].data.repository.pullRequests.pageInfo.hasNextPage == false' \
  "$gate_root/open-pr-pages.json" >/dev/null || fail "incomplete open-PR pagination"

# Build and validate the complete graph. The emitted order is the requested
# stack only, topologically ordered parent -> child; every open-PR cycle is
# rejected, and a selected chain may end only at the caller-approved root base.
ruby -r json -e '
  pages = JSON.parse(File.read(ARGV.fetch(0)))
  repo, target, root = ARGV.fetch(1), Integer(ARGV.fetch(2)), ARGV.fetch(3)
  prs = pages.flat_map { |page| page.dig("data", "repository", "pullRequests", "nodes") || abort("missing PR nodes") }
  abort("duplicate PR number") unless prs.map { |p| p.fetch("number") }.uniq.length == prs.length
  abort("fork or missing head repository") unless prs.all? { |p| p.dig("headRepository", "nameWithOwner") == repo }
  heads = prs.map { |p| p.fetch("headRefName") }
  abort("duplicate source branch") unless heads.uniq.length == heads.length
  by_head = prs.to_h { |p| [p.fetch("headRefName"), p] }
  visiting, visited = {}, {}
  visit = lambda do |node|
    key = node.fetch("headRefName"); abort("stack cycle") if visiting[key]
    return if visited[key]
    visiting[key] = true
    parent = by_head[node.fetch("baseRefName")]
    visit.call(parent) if parent
    visiting.delete(key); visited[key] = true
  end
  prs.each { |node| visit.call(node) }
  node = prs.select { |p| p.fetch("number") == target }
  abort("requested PR absent from complete open-PR graph") unless node.length == 1
  chain, seen = [], {}
  node = node.fetch(0)
  loop do
    key = node.fetch("headRefName"); abort("selected stack cycle") if seen[key]
    seen[key] = true; chain << node
    parent_ref = node.fetch("baseRefName")
    break if parent_ref == root
    node = by_head[parent_ref] or abort("selected stack parent missing")
  end
  puts chain.reverse.map { |p| p.fetch("number") }
' "$gate_root/open-pr-pages.json" "$base_repo" "$pr" "$stack_root_base" \
  >"$gate_root/stack-order.txt"
```

For each PR number in `stack-order.txt`, re-fetch its live head/base, run the
guarded rebase protocol, then request a new Copilot review and run the complete
two-snapshot gate. A parent review, approval, check, or manifest never approves
a child; a child may not be pushed before its parent dependency is current.

## PR descriptions and draft lifecycle

Prepare Markdown in a real file. Do not interpolate Markdown, backticks, or
escaped newlines through `--body` or shell command substitution.

```bash
set -euo pipefail

body_file="$(mktemp -t breakglass-pr-description.XXXXXX.md)"
vi "$body_file"                         # a known executable, not an EDITOR shell fragment
test -s "$body_file"

# The post-create verification writes into this run's private directory. Set it
# up before the first PR mutation so a failed verification cannot be caused by
# an unset path after the draft has already been created.
gate_root="$(mktemp -d)"
trap 'rm -rf "$gate_root"; rm -f "$body_file"' EXIT

# The caller supplies the actual intended base; do not silently substitute a
# repository default. A workflow that explicitly targets the default may derive
# it first, record that decision, then assign it here.
github_host=github.com
base_repo=BASE_OWNER/BASE_REPOSITORY
base_ref=INTENDED_BASE_REF
contract="./.github/scripts/pr-gate-contract.sh"
test -x "$contract" || { echo "missing executable PR-gate contract helper" >&2; exit 1; }
# Re-use the strict URL parser to validate the caller-supplied host/repository
# before any API or Git network action. A temporary PR number is only syntax.
IFS=$'\t' read -r parsed_host parsed_repo _ <<EOF
$($contract parse-pr-url "https://$github_host/$base_repo/pull/1")
EOF
test "$parsed_host" = "$github_host" && test "$parsed_repo" = "$base_repo" || {
  echo "invalid GitHub host or repository" >&2; exit 1;
}
hosted_repo="$github_host/$base_repo"
gh_pr() { env GH_HOST="$github_host" gh pr "$@"; }
gh_api() { env GH_HOST="$github_host" gh api --hostname "$github_host" "$@"; }
gh auth status --hostname "$github_host" >/dev/null || {
  echo "no authenticated gh session for the pinned GitHub host" >&2; exit 1;
}
git check-ref-format --branch "$base_ref" >/dev/null
head_ref="$(git branch --show-current)"
git check-ref-format --branch "$head_ref" >/dev/null

# Enumerate every remote and its push URLs immediately before draft creation.
# There must be exactly one verified same-repository endpoint for this branch;
# do not trust a remembered remote name or let Git choose a default.
if git config --get-regexp '^url\..*\.(insteadOf|pushInsteadOf)$' >/dev/null; then
  echo "URL rewrite configuration is present; refusing draft creation" >&2
  exit 1
fi
expected_https_remote="https://$github_host/$base_repo.git"
push_remote=""
for candidate in $(git remote); do
  fetch_url="$(git remote get-url "$candidate")"
  push_urls="$(git remote get-url --push --all "$candidate")"
  push_count="$(printf '%s\n' "$push_urls" | awk 'NF { count++ } END { print count + 0 }')"
  if test "$push_count" != 1; then
    printf 'rejecting remote %s: expected exactly one push URL\n' "$candidate" >&2
    continue
  fi
  push_url="$(printf '%s\n' "$push_urls" | sed -n '1p')"
  if test "$fetch_url" != "$expected_https_remote" || test "$push_url" != "$expected_https_remote"; then
    printf 'rejecting remote %s: endpoint is not the pinned HTTPS target repository\n' "$candidate" >&2
    continue
  fi
  test -z "$push_remote" || { echo "ambiguous verified remotes" >&2; exit 1; }
  push_remote="$candidate"
done
test -n "$push_remote" || { echo "no single verified push target" >&2; exit 1; }

# Re-fetch the actual source/base refs immediately before the draft mutation.
git fetch "$push_remote" \
  "refs/heads/$base_ref:refs/remotes/$push_remote/$base_ref" \
  "refs/heads/$head_ref:refs/remotes/$push_remote/$head_ref"
git rev-parse --verify "$push_remote/$base_ref^{commit}" >/dev/null
test "$(git rev-parse "$push_remote/$head_ref")" = "$(git rev-parse HEAD)"
source_oid="$(git rev-parse HEAD)"
base_oid="$(git rev-parse "$push_remote/$base_ref")"

pr_url="$(gh_pr create --repo "$hosted_repo" --draft \
  --head "$head_ref" --base "$base_ref" --title "feat: description" \
  --body-file "$body_file")"
printf '%s\n' "$pr_url"
IFS=$'\t' read -r created_host created_repo created_pr <<EOF
$($contract parse-pr-url "$pr_url")
EOF
pr="$created_pr"
test "$created_host" = "$github_host" && test "$created_repo" = "$base_repo" || {
  echo "PR creation returned a different GitHub host or repository" >&2; exit 1;
}
gh_pr view "$pr" --repo "$hosted_repo" \
  --json isDraft,headRefName,headRefOid,headRepository,baseRefName,baseRefOid,baseRepository \
  >"$gate_root/created-pr.json"
"$contract" verify-created-draft "$gate_root/created-pr.json" "$base_repo" \
  "$head_ref" "$source_oid" "$base_ref" "$base_oid"

# Use the same file-only rule for an existing PR description.
gh_pr edit "$pr" --repo "$hosted_repo" --body-file "$body_file"
```

Read the stored raw body, inspect `bodyHTML`, and check the rendered web page
for headings, newlines, links, dependency heads, scope, limitations, and test
evidence. Mark a draft ready only after the complete gate passes.

```bash
gh_pr view "$pr" --repo "$hosted_repo" --json body --jq .body
# shellcheck disable=SC2016
# GraphQL variables must reach gh unchanged.
gh_api graphql -f query='
  query($owner:String!, $repo:String!, $pr:Int!) {
    repository(owner:$owner, name:$repo) { pullRequest(number:$pr) { bodyHTML } }
  }
' -f owner="${base_repo%/*}" -f repo="${base_repo#*/}" -F pr="$pr" \
  --jq .data.repository.pullRequest.bodyHTML
gh_pr view "$pr" --repo "$hosted_repo" --web
```

The browser check is description-only. The separate fail-closed gate block is
the only place that marks a PR ready. No successful check, review, or absence
of new comments from an earlier head/base pair is reusable evidence.
