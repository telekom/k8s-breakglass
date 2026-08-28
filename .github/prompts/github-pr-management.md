# GitHub PR Management

Use this prompt when managing pull requests: reviewing, resolving threads,
rebasing, squashing, writing descriptions, and interacting with CI.

## Prerequisites

- GitHub CLI (`gh`) must be authenticated
- EMU (Enterprise Managed User) accounts cannot use GitHub MCP API for
  write operations — always use `gh` CLI instead

## Exact-Head Gate

Treat the current PR head **and base** as the unit of approval. A green check
or review from an earlier source/base pair does not approve a later push.

After **every** push, record the new head and do not mark the PR ready until
all of the following apply to that exact object ID:

1. Every required CI check has completed successfully for the current
   head/base pair. Inspect the expected check inventory as well as its
   conclusion; a single unrelated successful check is not sufficient.
2. The latest formal Copilot review is a submitted, non-dismissed `COMMENTED`
   review from the configured Copilot reviewer identity for that exact head.
3. Suppressed/minimized review comments have been inspected, and every
   unresolved review conversation has been resolved. Do not waive a thread
   merely by documenting a disposition unless the current repository ruleset
   explicitly permits that specific exception.

```bash
# Snapshot these values before inspecting checks and reviews. Re-run the
# complete gate if the final snapshot differs.
pr_snapshot() {
  gh pr view PR_NUMBER --repo BASE_OWNER/BASE_REPOSITORY \
    --json baseRefName,baseRefOid,headRefName,headRefOid,headRepository
}
before_snapshot="$(pr_snapshot)"
printf '%s\n' "$before_snapshot"

# CI output must be associated with the snapshot; see the CI rules below.
gh pr checks PR_NUMBER --watch --required

# Read head and base again after CI, reviews, and threads have been examined.
after_snapshot="$(pr_snapshot)"
test "$before_snapshot" = "$after_snapshot" || {
  echo "PR head/base changed; restart the complete exact-head gate" >&2
  exit 1
}
```

For automated gates, query the PR's `headRefOid`, `baseRefOid`, required check
runs, formal reviews (including each review's `commit.oid`), review threads,
and minimized comments through GitHub GraphQL. Paginate every connection until
`hasNextPage` is false. Repeat the complete snapshot after gathering the data;
if either head or base changed, discard the result and restart the gate.

GitHub may run `pull_request` workflows on a synthetic test-merge SHA, and
merge-queue workflows can run on a merge-queue candidate SHA. Therefore, do
not require every check-run SHA to equal `headRefOid`. Instead, verify each
required run/check is associated with the captured source `headRefOid` **and**
`baseRefOid`, then accept its selected synthetic merge or merge-queue SHA only
when that association is exact. A check for a different base, an earlier head,
or an unrelated successful run fails the gate.

For example, enumerate formal reviews with a separate paginated query, then
select the latest submitted result from the repository-configured exact Copilot
reviewer login rather than a coding-agent comment:

```bash
gh api graphql -f query='
  query($owner:String!, $repo:String!, $pr:Int!, $cursor:String) {
    repository(owner:$owner, name:$repo) {
      pullRequest(number:$pr) {
        headRefOid
        reviews(first:100, after:$cursor) {
          pageInfo { hasNextPage endCursor }
          nodes {
            author { login }
            state
            submittedAt
            commit { oid }
          }
        }
      }
    }
  }
' -f owner=telekom -f repo=REPO_NAME -F pr=PR_NUMBER -F cursor=null
```

Set `copilot_reviewer_login` to the known, repository-configured bot login; do
not identify Copilot from a display name, an `@copilot` mention, or a similarly
named account. The selected review must have that exact `author.login`,
`state: COMMENTED`, a non-null `submittedAt`, no dismissed state, and a
`commit.oid` exactly equal to the captured `headRefOid`. An older matching
state is insufficient. Repeat with `cursor` set to `endCursor` until all review
pages have been inspected.

## Requesting a Formal Copilot Review

Request Copilot as a PR reviewer; do **not** use an `@copilot review` comment.
That comment invokes the coding agent and is not a formal pull-request review
request.

```bash
gh pr edit PR_NUMBER --add-reviewer @copilot
```

The equivalent is GitHub's requested-reviewers REST endpoint with the Copilot
reviewer account. Use it only where the repository's GitHub configuration
supports that bot reviewer.

Copilot does not automatically re-review every pushed commit unless the
repository has explicitly configured automatic re-reviews. After each pushed
head, request another formal review when necessary and verify the resulting
review commit OID against the new PR head. Never infer a new review from an
older review, a comment, or the absence of new threads.

## Checking PR Review Threads

Use this GraphQL query to list all review threads and their resolution status:

```bash
gh api graphql -f query='
  query($owner:String!, $repo:String!, $pr:Int!, $cursor:String) {
    repository(owner:$owner, name:$repo) {
      pullRequest(number:$pr) {
        reviewThreads(first:100, after:$cursor) {
          pageInfo { hasNextPage endCursor }
          nodes {
            id
            isResolved
            isOutdated
            comments(first:100) {
              pageInfo { hasNextPage endCursor }
              nodes {
                id
                body
                author { login }
                path
                line
                createdAt
                isMinimized
                minimizedReason
              }
            }
          }
        }
      }
    }
  }
' -f owner=telekom -f repo=REPO_NAME -F pr=PR_NUMBER -F cursor=null
```

Repeat the thread query with `cursor` set to `endCursor` until the thread
`hasNextPage` is false. Each thread's comments have a separate cursor: when a
thread's `comments.pageInfo.hasNextPage` is true, page that thread by its
returned thread ID before deciding the conversation is complete.

```bash
gh api graphql -f query='
  query($thread:ID!, $cursor:String) {
    node(id:$thread) {
      ... on PullRequestReviewThread {
        comments(first:100, after:$cursor) {
          pageInfo { hasNextPage endCursor }
          nodes {
            id
            body
            author { login }
            path
            line
            createdAt
            isMinimized
            minimizedReason
          }
        }
      }
    }
  }
' -F thread=THREAD_ID -F cursor=null
```

Inspect minimized comments as deliberately as visible ones: minimizing is not
a resolution or a waiver. Every unresolved review thread, including an outdated
one, blocks the ready gate unless an applicable current repository ruleset
explicitly permits the exception.

## Resolving Review Threads

After fixing an issue raised in a review thread, resolve it:

```bash
# Single thread
gh api graphql -f query='
  mutation {
    resolveReviewThread(input: {threadId: "THREAD_ID"}) {
      thread { isResolved }
    }
  }
'

# Multiple threads at once (use aliases)
gh api graphql -f query='
  mutation {
    t1: resolveReviewThread(input: {threadId: "ID_1"}) { thread { isResolved } }
    t2: resolveReviewThread(input: {threadId: "ID_2"}) { thread { isResolved } }
  }
'
```

## Rebasing on Main

Prefer a short, signed stack: put follow-up fixes in signed child commits and
rebase only when a current base is actually required. Before rewriting a
published branch, fetch it, capture the exact remote branch OID, and make sure
the rewrite is authorized for that branch.

This repository's policy is same-repository PRs only. Refuse to push a fork
branch; never guess that `origin`, `main`, or the checked-out branch is the PR
source. Derive the live PR head repository/ref and base repository/ref first,
then select exactly one verified local remote for that head repository.

```bash
# Start from the actual target PR URL, not a branch name or local remote.
pr_url="https://github.example/BASE_OWNER/BASE_REPOSITORY/pull/PR_NUMBER"
pr_url="$(gh pr view "$pr_url" --json url --jq .url)"
base_repo="$(printf '%s\n' "$pr_url" | awk -F/ '{print $(NF-3) "/" $(NF-2)}')"
pr="$(printf '%s\n' "$pr_url" | awk -F/ '{print $NF}')"
case "$base_repo" in */*) ;; *) echo "invalid PR URL" >&2; exit 1;; esac
pr_data="$(gh pr view "$pr" --repo "$base_repo" \
  --json baseRefName,baseRefOid,headRefName,headRefOid,headRepository)"
base_ref="$(jq -r .baseRefName <<<"$pr_data")"
base_oid="$(jq -r .baseRefOid <<<"$pr_data")"
head_ref="$(jq -r .headRefName <<<"$pr_data")"
head_oid="$(jq -r .headRefOid <<<"$pr_data")"
head_repo="$(jq -r .headRepository.nameWithOwner <<<"$pr_data")"

# The current policy does not authorize pushes to forks.
test "$head_repo" = "$base_repo" || {
  echo "refusing to rewrite or push fork PR $head_repo" >&2
  exit 1
}

# Match a configured remote to the actual PR head repository, rather than
# assuming that a remote named origin is safe. Refuse ambiguity.
push_remote=""
for candidate in $(git remote); do
  candidate_repo="$(gh repo view "$(git remote get-url "$candidate")" \
    --json nameWithOwner --jq .nameWithOwner 2>/dev/null || true)"
  test "$candidate_repo" = "$head_repo" || continue
  test -z "$push_remote" || {
    echo "multiple remotes resolve to PR head repository" >&2
    exit 1
  }
  push_remote="$candidate"
done
test -n "$push_remote" || {
  echo "no configured remote matches PR head repository" >&2
  exit 1
}

git fetch "$push_remote" \
  "refs/heads/$base_ref:refs/remotes/$push_remote/$base_ref" \
  "refs/heads/$head_ref:refs/remotes/$push_remote/$head_ref"
test "$(git rev-parse "$push_remote/$base_ref")" = "$base_oid" || {
  echo "PR base changed; refresh PR metadata before rebasing" >&2
  exit 1
}
remote_head="$(git rev-parse "$push_remote/$head_ref")"
test "$remote_head" = "$head_oid" || {
  echo "PR head changed; refresh PR metadata before rebasing" >&2
  exit 1
}
local_branch="$(git branch --show-current)"
test "$local_branch" = "$head_ref" || {
  echo "checked-out branch is not the PR head ref" >&2
  exit 1
}
test -z "$(git status --porcelain)" || {
  echo "refusing to rebase a dirty worktree" >&2
  exit 1
}
git rebase --gpg-sign "$push_remote/$base_ref"

# If conflicts arise, resolve them and continue:
git add -- path/to/resolved-conflict.go path/to/other-resolved-file.yaml
git rebase --continue

# --gpg-sign preserves signing for rewritten commits. Configure a suitable
# signing key in advance; do not disable signing to bypass a local setup
# problem. Check every rewritten commit before pushing.
git log --show-signature --format=fuller "$push_remote/$base_ref..HEAD"

# Only after the rebase is verified, update this personal branch without
# overwriting a collaborator's intervening push. Re-read the live PR metadata
# immediately before this command and stop if head/base repository, ref, or OID
# changed from pr_data.
current_pr_data="$(gh pr view "$pr" --repo "$base_repo" \
  --json baseRefName,baseRefOid,headRefName,headRefOid,headRepository)"
test "$current_pr_data" = "$pr_data" || {
  echo "PR metadata changed; refresh and restart before pushing" >&2
  exit 1
}
git push --force-with-lease="refs/heads/$head_ref:$remote_head" \
  "$push_remote" "HEAD:refs/heads/$head_ref"
```

Do not use a broad `--force`. If the lease no longer matches, stop, fetch, and
reconcile the remote change before deciding whether to rebase again.

## Signed Commit Hygiene

Keep commits signed. Do not disable signing for rebases, squashes, or amends.
If a PR needs a single commit, prefer GitHub's signed squash-merge policy or a
carefully reviewed interactive rebase on an unpublished personal branch.

```bash
git commit -S -m "docs: describe the change"
git commit --amend -S --no-edit
```

Do not use reset-based squashing. It discards the reviewed commit structure and
makes a lease-safe, auditable update harder. For stacked PRs, rebase each child
in dependency order and update only the affected personal branch with an
explicit `--force-with-lease` after checking its recorded remote OID.

## Checking CI Status

```bash
# List all CI checks for a PR
gh pr checks PR_NUMBER

# Watch CI in real-time
gh pr checks PR_NUMBER --watch

# Get detailed check run output
gh run view RUN_ID --log-failed
```

Before accepting the result, compare every required run/check's PR association
to the captured `headRefOid` and `baseRefOid`. Its SHA can equal the source
head only for head-based workflows; for pull-request test merges or merge
queues, validate the selected synthetic candidate for that same source/base
pair instead. Re-run the complete gate after any branch or base update,
including an automatic rebase or a merge into the base branch.

## Adding PR Comments

```bash
# General comment
gh pr comment PR_NUMBER --body "Comment text"

# Reply to a review thread (use the thread's comment ID)
gh api graphql -f query='
  mutation {
    addPullRequestReviewComment(input: {
      pullRequestReviewId: "REVIEW_ID",
      inReplyTo: "COMMENT_ID",
      body: "Reply text"
    }) { comment { id } }
  }
'
```

## Creating PRs

Write the description into a real Markdown file. Do not interpolate complex
Markdown, backticks, variables, or escaped newlines through an inline
`--body` argument or shell command substitution.

```bash
# Edit a real temporary Markdown file using an editor or a repository template.
body_file="$(mktemp -t breakglass-pr-description.XXXXXX.md)"
"${EDITOR:?set EDITOR to populate the PR description}" "$body_file"
test -s "$body_file" || {
  echo "refusing to create or edit a PR with an empty description" >&2
  exit 1
}

gh pr create \
  --title "feat: description" \
  --body-file "$body_file" \
  --base main

# The same rule applies to edits.
gh pr edit PR_NUMBER --body-file "$body_file"

# Read the stored body back and inspect the rendered PR to confirm headings,
# newlines, links, dependency heads, scope, limitations, and test evidence.
gh pr view PR_NUMBER --json body --jq .body
gh api graphql -f query='
  query($owner:String!, $repo:String!, $pr:Int!) {
    repository(owner:$owner, name:$repo) {
      pullRequest(number:$pr) { bodyHTML }
    }
  }
' -f owner=BASE_OWNER -f repo=BASE_REPOSITORY -F pr=PR_NUMBER --jq \
  .data.repository.pullRequest.bodyHTML
gh pr view PR_NUMBER --web
```

Compare the raw body to the source file, inspect `bodyHTML`, and verify the
rendered web page before relying on the description. The raw API body alone
does not prove Markdown rendered as intended.

## Workflow Tips

1. **Gate each pushed head/base pair** — collect exact OIDs, required CI
   association, formal-review commit OID, minimized comments, and every
   unresolved thread. Copilot does not inherently review every push.
2. **Resolve threads only after fixing** — don't resolve a thread until the
   code change is pushed and the new head has been checked.
3. **Batch GraphQL mutations** — resolve multiple threads in one API call
   using aliases (`t1:`, `t2:`, etc.).
4. **Prefer stacked signed commits** — rebase only when necessary, preserve
   signatures, and use an explicit `--force-with-lease` only for an authorized
   rewrite of the affected branch.
5. **Verify the formal review** — a Copilot review must be a formal review on
   the current head, not an `@copilot review` coding-agent comment.
