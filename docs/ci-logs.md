# CI/CD Logs & Artifacts

This guide describes how to retrieve CI/CD logs and artifacts for review.

## Fetch latest main logs (gh CLI)

```bash
gh run list --branch main -L 1 --json databaseId,displayTitle,createdAt,conclusion,status
# Then fetch full logs for that run ID
GH_PAGER=cat gh run view <run-id> --log > /tmp/ci-main-latest.log
```

## Download artifacts for a run

```bash
# List artifacts for a run
GH_PAGER=cat gh api repos/telekom/k8s-breakglass/actions/runs/<run-id>/artifacts

# Download all artifacts
gh run download <run-id> -D /tmp/ci-artifacts/<run-id>
```

## Notes

- GitHub Actions artifacts remain the source of truth.
- Use local paths (e.g., `/tmp`) for ad-hoc reviews.
