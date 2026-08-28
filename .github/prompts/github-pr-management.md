# GitHub PR Management

Use this prompt when managing pull requests: reviewing, resolving threads,
rebasing, squashing, writing descriptions, and interacting with CI.

## Prerequisites

- GitHub CLI (`gh`) must be authenticated
- EMU (Enterprise Managed User) accounts cannot use GitHub MCP API for
  write operations — always use `gh` CLI instead

## Exact-Head Gate

Treat the commit currently at the PR head as the unit of approval. A green
check or review on an earlier commit does not approve a later push.

After **every** push, record the new head and do not mark the PR ready until
all of the following apply to that exact object ID:

1. Every required CI check has completed successfully for the current head.
   Inspect the expected check inventory as well as its conclusion; a single
   unrelated successful check is not sufficient.
2. The latest formal Copilot review was submitted for that same head (if
   Copilot review is required for the repository).
3. Suppressed/minimized review comments have been inspected, and every
   non-outdated unresolved review thread has either been fixed and resolved or
   has an explicit, documented disposition.

```bash
# Save this value before inspecting checks and reviews. Re-run it after each
# push; never reuse an OID recorded for an earlier head.
head_oid="$(gh pr view PR_NUMBER --json headRefOid --jq .headRefOid)"
printf '%s\n' "$head_oid"

# CI status is useful only after comparing its commit to head_oid.
gh pr checks PR_NUMBER --watch --required
```

For automated gates, query the PR's `headRefOid`, required check runs, formal
reviews (including each review's `commit.oid`), review threads, and minimized
comments through GitHub GraphQL. Paginate each connection until `hasNextPage`
is false. Fail the gate unless the selected Copilot review's `commit.oid`
equals `headRefOid`, all required checks apply to that OID and succeeded, and
there are no unreviewed minimized comments or non-outdated unresolved threads.

For example, enumerate formal reviews with a separate paginated query, then
select the latest submitted Copilot reviewer result rather than a coding-agent
comment:

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

Compare the formal review's `commit.oid` to the displayed `headRefOid` exactly;
an older matching review state is insufficient. Repeat with `cursor` set to
`endCursor` until all review pages have been inspected.

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
              nodes {
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

Repeat the query with `cursor` set to `endCursor` until `hasNextPage` is
false. Inspect minimized comments as deliberately as visible ones: minimizing
is not a resolution or a waiver. Only unresolved threads with
`isOutdated: false` block the ready gate, but outdated threads still deserve a
documented decision when they raise a safety concern.

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

```bash
git fetch origin main
branch="$(git branch --show-current)"
remote_head="$(git rev-parse "origin/$branch")"
git rebase --gpg-sign origin/main

# If conflicts arise, resolve them and continue:
git add -A
git rebase --continue

# --gpg-sign preserves signing for rewritten commits. Configure a suitable
# signing key in advance; do not disable signing to bypass a local setup
# problem. Check every rewritten commit before pushing.
git log --show-signature --format=fuller origin/main..HEAD

# Only after the rebase is verified, update this personal branch without
# overwriting a collaborator's intervening push.
git push --force-with-lease="refs/heads/$branch:$remote_head" origin "$branch"
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

Before accepting the result, compare the CI run's head SHA and every required
check run's SHA to the `head_oid` recorded in the exact-head gate. Re-run the
gate after any branch update, including an automatic rebase or a merge from
main.

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

gh pr create \
  --title "feat: description" \
  --body-file "$body_file" \
  --base main

# The same rule applies to edits.
gh pr edit PR_NUMBER --body-file "$body_file"

# Read the stored body back and inspect the rendered PR to confirm headings,
# newlines, links, dependency heads, scope, limitations, and test evidence.
gh pr view PR_NUMBER --json body --jq .body
```

## Workflow Tips

1. **Gate each pushed head** — collect its exact OID, required CI result,
   formal-review commit OID, minimized comments, and unresolved current
   threads. Copilot does not inherently review every push.
2. **Resolve threads only after fixing** — don't resolve a thread until the
   code change is pushed and the new head has been checked.
3. **Batch GraphQL mutations** — resolve multiple threads in one API call
   using aliases (`t1:`, `t2:`, etc.).
4. **Prefer stacked signed commits** — rebase only when necessary, preserve
   signatures, and use an explicit `--force-with-lease` only for an authorized
   rewrite of the affected branch.
5. **Verify the formal review** — a Copilot review must be a formal review on
   the current head, not an `@copilot review` coding-agent comment.
