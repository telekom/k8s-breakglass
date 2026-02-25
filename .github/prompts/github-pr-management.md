# GitHub PR Management

Use this prompt when managing pull requests: reviewing, resolving threads,
rebasing, squashing, and interacting with CI.

## Prerequisites

- GitHub CLI (`gh`) must be authenticated
- EMU (Enterprise Managed User) accounts cannot use GitHub MCP API for
  write operations — always use `gh` CLI instead

## Checking PR Review Threads

Use this GraphQL query to list all review threads and their resolution status:

```bash
gh api graphql -f query='
  query($owner:String!, $repo:String!, $pr:Int!) {
    repository(owner:$owner, name:$repo) {
      pullRequest(number:$pr) {
        reviewThreads(first:100) {
          nodes {
            id
            isResolved
            isOutdated
            comments(first:1) {
              nodes {
                body
                author { login }
                path
                line
                createdAt
              }
            }
          }
        }
      }
    }
  }
' -f owner=telekom -f repo=REPO_NAME -F pr=PR_NUMBER
```

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

```bash
git fetch origin main
git rebase origin/main

# If conflicts arise, resolve them and continue:
git add -A
git rebase --continue

# Always use gpg-sign=false and skip editor:
GIT_EDITOR=true git -c commit.gpgsign=false rebase --continue
```

## Squashing Commits

Squash all commits on a feature branch into one:

```bash
# Count commits ahead of main
COMMITS=$(git rev-list --count origin/main..HEAD)

# Interactive rebase, squash all into first
GIT_EDITOR="sed -i '' '2,\$s/^pick/squash/'" git -c commit.gpgsign=false rebase -i HEAD~$COMMITS

# Or reset-based squash (simpler):
git reset --soft origin/main
git -c commit.gpgsign=false commit -m "feat: description (#PR)"
```

## Amending and Force-Pushing

After fixing review comments, amend the squashed commit:

```bash
git add -A
git -c commit.gpgsign=false commit --amend --no-edit
git push --force-with-lease
```

## Checking CI Status

```bash
# List all CI checks for a PR
gh pr checks PR_NUMBER

# Watch CI in real-time
gh pr checks PR_NUMBER --watch

# Get detailed check run output
gh run view RUN_ID --log-failed
```

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

```bash
gh pr create \
  --title "feat: description" \
  --body "## Summary\n\nDescription\n\n## Changes\n\n- Change 1\n- Change 2" \
  --base main
```

## Workflow Tips

1. **Always check threads after push** — Copilot reviewer adds new threads
   on every push. Run the thread-check query after each force-push.
2. **Resolve threads only after fixing** — don't resolve a thread until the
   code change is pushed.
3. **Batch GraphQL mutations** — resolve multiple threads in one API call
   using aliases (`t1:`, `t2:`, etc.).
4. **Force-push with lease** — always use `--force-with-lease` to avoid
   overwriting collaborators' changes.
5. **Verify 0 unresolved** — before marking a PR ready, confirm all threads
   are resolved.
