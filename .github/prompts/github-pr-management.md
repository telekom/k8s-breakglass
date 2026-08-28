# GitHub PR Management

Use this prompt to create, update, review, rebase, and ready a pull request.
Treat a PR as approved only when one complete, current evidence snapshot passes.

## Repository and command scope

- Use `--repo BASE_OWNER/BASE_REPOSITORY` with every `gh pr` and `gh run`
  command. Do not rely on the checked-out repository or a remote named
  `origin`.
- This task's user-directed policy permits direct same-repository branches
  only. Refuse fork pushes; do not repurpose this policy as a repository rule.
- The installed `gh api` has no `--repo` flag. Its REST paths must include
  `repos/$base_repo/...`; its GraphQL calls must include explicit `owner` and
  `repo` variables.

## Formal review requirements

Request a formal Copilot review; do not write an `@copilot review` comment.
The comment invokes the coding agent and is not a pull-request review request.

```bash
gh pr edit PR_NUMBER --repo BASE_OWNER/BASE_REPOSITORY --add-reviewer @copilot
```

Use the known, repository-configured Copilot reviewer login, never a display
name or similarly named account. The selected review must be the newest review
from that exact login with all of these properties:

- `state` is `COMMENTED`, not dismissed;
- `submittedAt` is non-null and later than the recorded review-request time;
- `commit.oid` equals the captured PR `headRefOid`.

Copilot does not re-review every push unless the repository explicitly
configures it. A head or base OID change restarts the gate and requires a fresh
formal Copilot request/review. Its `COMMENTED` review is not a human approval:
the captured `reviewDecision` and the actual branch ruleset/code-owner policy
must independently show the current human and code-owner approvals required for
that same head/base pair. A review commit OID does not bind the base: the review
request timestamp is recorded after observing the pair, and final identity
comparison provides the required base binding.

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
pr_url="https://github.example/BASE_OWNER/BASE_REPOSITORY/pull/PR_NUMBER"
base_repo="$(printf '%s\n' "$pr_url" | awk -F/ '{print $(NF-3) "/" $(NF-2)}')"
pr="$(printf '%s\n' "$pr_url" | awk -F/ '{print $NF}')"
case "$base_repo" in */*) ;; *) fail "invalid PR URL";; esac
case "$pr" in ''|*[!0-9]*) fail "invalid PR number";; esac

gate_root="$(mktemp -d)"
trap 'rm -rf "$gate_root"' EXIT
observed="$gate_root/observed.json"

capture_identity() {
  gh api graphql -f query='
    query($owner:String!, $repo:String!, $pr:Int!) {
      repository(owner:$owner, name:$repo) {
        pullRequest(number:$pr) {
          headRefName headRefOid baseRefName baseRefOid
          headRepository { nameWithOwner }
          reviewDecision
          potentialMergeCommit { oid }
          mergeQueueEntry { id }
        }
      }
    }
  ' -f owner="${base_repo%/*}" -f repo="${base_repo#*/}" -F pr="$pr"
}

# Observe the source/base before requesting a fresh review.
capture_identity >"$observed"
jq -e '.data.repository.pullRequest.headRefOid and
       .data.repository.pullRequest.baseRefOid and
       .data.repository.pullRequest.headRepository.nameWithOwner' \
  "$observed" >/dev/null || fail "incomplete PR identity"

request_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n --arg requestAt "$request_at" '{requestAt: $requestAt}' \
  >"$gate_root/review-request.json"
gh pr edit "$pr" --repo "$base_repo" --add-reviewer @copilot
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
evidence capture in `$gate_root/verified`. Its `identity.json` must byte-match
`observed.json` before using it. Validate the evidence, then repeat the *same*
collection into `$gate_root/final` immediately before ready/merge. Both captures
must use the same filenames and include a fresh `identity.json`.

```bash
gate_dir="$gate_root/verified"
mkdir -p "$gate_dir"
cp "$gate_root/review-request.json" "$gate_dir/review-request.json"
capture_identity >"$gate_dir/identity.json"
cmp -s "$observed" "$gate_dir/identity.json" || \
  fail "PR head/base or candidate changed; restart the complete gate"
head_oid="$(jq -r '.data.repository.pullRequest.headRefOid' "$gate_dir/identity.json")"
base_oid="$(jq -r '.data.repository.pullRequest.baseRefOid' "$gate_dir/identity.json")"
candidate_oid="$(jq -r \
  '.data.repository.pullRequest.potentialMergeCommit.oid // .data.repository.pullRequest.headRefOid' \
  "$gate_dir/identity.json")"
```

### Evidence that one gate snapshot must contain

Capture every page of each connection. A complete snapshot contains:

| Evidence | Required fields and decision |
| --- | --- |
| PR identity | `headRefOid`, `baseRefOid`, head repository/ref, base ref, test-merge SHA, `reviewDecision` |
| Formal reviews | reviewer `author.login`, state, `submittedAt`, `commit.oid`; select the newest configured Copilot review after `request_at` |
| Human approval | `reviewDecision` and current branch-ruleset/code-owner evidence for the pair; Copilot does not satisfy this row |
| Threads and comments | every thread ID/resolution/outdated state and every comment ID, minimized state/reason, author, path, line, and timestamp |
| Checks | complete expected inventory, result, `head_sha`, check-suite ID, and `CheckRun.app.owner.login`, `CheckRun.app.slug`, and `CheckRun.app.id` |
| Check suites | suite ID, `head_sha`, app/provider identity, and each associated PR's repository, head SHA/ref, and base SHA/ref |

Use repository rules/required-workflow configuration as the source of the full
expected inventory and allowed provider identities. For this task every
expected job must conclude `SUCCESS`. `NEUTRAL` or `SKIPPED` is acceptable only
when the current rules explicitly name that exact job and provider as an
intentional exception; record the rule source and reason. Never silently turn a
non-success result into a pass.

The following commands provide the raw, paginated review/thread/check material.
Save each response under the gate directory and normalize it with sorted JSON
before comparing snapshots.

```bash
# Formal reviews; evaluate the exact-login/latest/COMMENTED/time/head predicate.
gh api graphql --paginate --slurp -f query='
  query($owner:String!, $repo:String!, $pr:Int!, $endCursor:String) {
    repository(owner:$owner, name:$repo) {
      pullRequest(number:$pr) {
        reviews(first:100, after:$endCursor) {
          pageInfo { hasNextPage endCursor }
          nodes { author { login } state submittedAt commit { oid } }
        }
      }
    }
  }
' -f owner="${base_repo%/*}" -f repo="${base_repo#*/}" -F pr="$pr" \
  -F endCursor=null >"$gate_dir/reviews.json"

copilot_reviewer_login=REPOSITORY_CONFIGURED_COPILOT_LOGIN
jq -e --arg login "$copilot_reviewer_login" --arg head "$head_oid" \
  --arg requested "$request_at" '
  [ .[] | .data.repository.pullRequest.reviews.nodes[] |
    select(.author.login == $login) ] |
  if length == 0 then false else max_by(.submittedAt) |
    (.state == "COMMENTED" and .submittedAt != null and
     .submittedAt >= $requested and .commit.oid == $head)
  end
' "$gate_dir/reviews.json" >/dev/null || fail "missing current formal Copilot review"

# All review threads. Paginate every returned thread's comments separately.
gh api graphql --paginate --slurp -f query='
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

thread_number=0
jq -r '.[].data.repository.pullRequest.reviewThreads.nodes[].id' \
  "$gate_dir/threads.json" | while IFS= read -r thread_id; do
    thread_number=$((thread_number + 1))
    gh api graphql --paginate --slurp -f query='
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
  done
```

Every unresolved thread blocks the gate, including an outdated thread, unless
the current ruleset expressly permits that precise exception. Minimized is not
resolved. Resolve a thread only after its fix is present in the current head.

```bash
# REST carries check runs and suites; its full path scopes gh api explicitly.
for oid in "$head_oid" "$candidate_oid"; do
  gh api --paginate --slurp \
    "repos/$base_repo/commits/$oid/check-runs?per_page=100" \
    >"$gate_dir/check-runs-$oid.json"
  gh api --paginate --slurp \
    "repos/$base_repo/commits/$oid/check-suites?per_page=100" \
    >"$gate_dir/check-suites-$oid.json"
done
```

Join each expected check run to its suite. The suite's associated PR must name
the captured repository, `head_oid`/head ref, and `base_oid`/base ref. A run on
`candidate_oid` is valid only with that exact association; an unrelated green
run, a run for an earlier head, or one for a different base fails.

Before marking ready or merging, create a normalized, sorted manifest from all
the files above plus the expected-check inventory and ruleset evidence. Validate
the formal-Copilot predicate, human/code-owner approval, zero unpermitted
unresolved threads, and every expected check/provider/suite association. Then
capture the **entire** evidence set again and compare the two manifests:

```bash
manifest_snapshot() {
  snapshot="$1"
  find "$snapshot" -type f -name '*.json' -print | LC_ALL=C sort |
    while IFS= read -r json; do
      relative="${json#"$snapshot"/}"
      printf '%s\t' "$relative"
      jq -S -c . "$json"
    done >"$snapshot/gate.jsonl"
}

# After validating verified/, run every identity/review/thread/check collector
# above again with gate_dir="$gate_root/final". Include expected inventory and
# ruleset evidence JSON in both directories, then reject any change.
manifest_snapshot "$gate_root/verified"
manifest_snapshot "$gate_root/final"
cmp -s "$gate_root/verified/gate.jsonl" "$gate_root/final/gate.jsonl" || \
  fail "gate evidence changed; restart from identity and request a new review"
```

The final capture must still have the observed head/base pair. A changed head or
base invalidates Copilot, human approval, checks, and threads; restart rather
than carrying any evidence forward.

## Rebasing a same-repository PR safely

Use signed child commits where possible. Rewrite only an authorized direct PR
branch, and only after deriving its live source and base from the PR URL.

```bash
set -euo pipefail

pr_data="$(gh pr view "$pr" --repo "$base_repo" \
  --json baseRefName,baseRefOid,headRefName,headRefOid,headRepository)"
base_ref="$(jq -r .baseRefName <<<"$pr_data")"
base_oid="$(jq -r .baseRefOid <<<"$pr_data")"
head_ref="$(jq -r .headRefName <<<"$pr_data")"
head_oid="$(jq -r .headRefOid <<<"$pr_data")"
head_repo="$(jq -r .headRepository.nameWithOwner <<<"$pr_data")"
test "$head_repo" = "$base_repo" || { echo "refusing fork push" >&2; exit 1; }

# A selected remote must have exactly one push URL, and both its fetch and push
# targets must resolve to the current PR head repository.
push_remote=""
for candidate in $(git remote); do
  fetch_repo="$(gh repo view "$(git remote get-url "$candidate")" \
    --json nameWithOwner --jq .nameWithOwner 2>/dev/null || :)"
  push_urls="$(git remote get-url --push --all "$candidate")"
  push_count="$(printf '%s\n' "$push_urls" | awk 'NF { count++ } END { print count + 0 }')"
  test "$push_count" = 1 || continue
  push_url="$(printf '%s\n' "$push_urls" | sed -n '1p')"
  push_repo="$(gh repo view "$push_url" --json nameWithOwner --jq .nameWithOwner \
    2>/dev/null || :)"
  test "$fetch_repo" = "$head_repo" || continue
  test "$push_repo" = "$head_repo" || continue
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

signature_statuses="$(git log --format='%G?' "$push_remote/$base_ref..HEAD")"
printf '%s\n' "$signature_statuses"
if printf '%s\n' "$signature_statuses" | grep -Eq '[^G]'; then
  echo "rewritten commits are not all validly signed" >&2
  exit 1
fi

# Re-read live PR metadata; any movement means start over.
test "$(gh pr view "$pr" --repo "$base_repo" \
  --json baseRefName,baseRefOid,headRefName,headRefOid,headRepository)" = "$pr_data"
git push --force-with-lease="refs/heads/$head_ref:$remote_head" \
  "$push_remote" "HEAD:refs/heads/$head_ref"
```

If a rebase stops, resolve and stage only the named conflict paths, then
continue; otherwise run `git rebase --abort`. After either path, rerun every
post-rebase guard before a push. Never use broad `--force`, reset-based squash,
unsigned amend, or `git add -A`.

## PR descriptions and draft lifecycle

Prepare Markdown in a real file. Do not interpolate Markdown, backticks, or
escaped newlines through `--body` or shell command substitution.

```bash
set -euo pipefail

body_file="$(mktemp -t breakglass-pr-description.XXXXXX.md)"
vi "$body_file"                         # a known executable, not an EDITOR shell fragment
test -s "$body_file"

# Use the actual intended base, not a hardcoded main. Resolve the default only
# when that is the intended target; otherwise set and validate the release base.
base_repo=BASE_OWNER/BASE_REPOSITORY
base_ref="$(gh repo view "$base_repo" --json defaultBranchRef --jq .defaultBranchRef.name)"
head_ref="$(git branch --show-current)"

# The branch must already be pushed to one preverified same-repository target.
push_remote=REMOTE_VERIFIED_FOR_THIS_BRANCH
push_urls="$(git remote get-url --push --all "$push_remote")"
test "$(printf '%s\n' "$push_urls" | awk 'NF { count++ } END { print count + 0 }')" = 1
push_url="$(printf '%s\n' "$push_urls" | sed -n '1p')"
test "$(gh repo view "$(git remote get-url "$push_remote")" \
  --json nameWithOwner --jq .nameWithOwner)" = "$base_repo"
test "$(gh repo view "$push_url" --json nameWithOwner --jq .nameWithOwner)" = "$base_repo"
git fetch "$push_remote" "refs/heads/$head_ref:refs/remotes/$push_remote/$head_ref"
test "$(git rev-parse "$push_remote/$head_ref")" = "$(git rev-parse HEAD)"

pr_url="$(gh pr create --repo "$base_repo" --draft \
  --head "$head_ref" --base "$base_ref" --title "feat: description" \
  --body-file "$body_file")"
printf '%s\n' "$pr_url"

# Use the same file-only rule for an existing PR description.
gh pr edit PR_NUMBER --repo "$base_repo" --body-file "$body_file"
```

Read the stored raw body, inspect `bodyHTML`, and check the rendered web page
for headings, newlines, links, dependency heads, scope, limitations, and test
evidence. Mark a draft ready only after the complete gate passes.

```bash
gh pr view PR_NUMBER --repo "$base_repo" --json body --jq .body
gh api graphql -f query='
  query($owner:String!, $repo:String!, $pr:Int!) {
    repository(owner:$owner, name:$repo) { pullRequest(number:$pr) { bodyHTML } }
  }
' -f owner="${base_repo%/*}" -f repo="${base_repo#*/}" -F pr=PR_NUMBER \
  --jq .data.repository.pullRequest.bodyHTML
gh pr view PR_NUMBER --repo "$base_repo" --web
gh pr ready PR_NUMBER --repo "$base_repo"
```

Do not run the final `gh pr ready` command until the full gate snapshot has
passed unchanged. No successful check, review, or absence of new comments from
an earlier head/base pair is reusable evidence.
