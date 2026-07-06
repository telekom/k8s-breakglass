#!/usr/bin/env bash

set -euo pipefail

repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
sha="${GITHUB_SHA:?GITHUB_SHA is required}"
current_run_id="${GITHUB_RUN_ID:-}"

filter_current_run='
  def current_run_url:
    if $current_run_id == "" then false
    else
      (((.details_url // "") | contains("/actions/runs/" + $current_run_id + "/")) or
       ((.html_url // "") | contains("/actions/runs/" + $current_run_id + "/")))
    end;
  map(select(current_run_url | not))
'

latest_runs_by_check='
  def check_key:
    [((.app.id // .app.slug // .app.name // "unknown") | tostring), (.name // "")];
  def run_order:
    [(.started_at // .completed_at // .created_at // .updated_at // ""), (.id // 0)];
  sort_by(check_key)
  | group_by(check_key)
  | map(max_by(run_order))
'

if [ -n "${CHECK_RUNS_JSON:-}" ]; then
  all_runs="$(jq -c '
    if type == "object" and has("check_runs") then .check_runs
    elif type == "array" then .
    else [.]
    end
  ' <<< "${CHECK_RUNS_JSON}")"
else
  all_runs="$(
    gh api --paginate "repos/${repo}/commits/${sha}/check-runs?per_page=100" \
      --jq '.check_runs[]' | jq -s -c '.'
  )"
fi

filtered_runs="$(jq -c --arg current_run_id "${current_run_id}" "${filter_current_run}" <<< "${all_runs}")"

ignored_count="$(( $(jq 'length' <<< "${all_runs}") - $(jq 'length' <<< "${filtered_runs}") ))"
if [ "${ignored_count}" -gt 0 ]; then
  echo "Ignoring ${ignored_count} check run(s) from current release workflow run ${current_run_id}."
fi

runs="$(jq -c "${latest_runs_by_check}" <<< "${filtered_runs}")"
superseded_count="$(( $(jq 'length' <<< "${filtered_runs}") - $(jq 'length' <<< "${runs}") ))"
if [ "${superseded_count}" -gt 0 ]; then
  echo "Ignoring ${superseded_count} superseded check run attempt(s); evaluating latest check run per app/name."
fi

failures="$(
  jq -r '
    .[]
    | select(.conclusion == "failure" or .conclusion == "timed_out" or .conclusion == "action_required" or .conclusion == "cancelled")
    | .name
  ' <<< "${runs}"
)"
if [ -n "${failures}" ]; then
  echo "::error::CI checks failed for commit ${sha}: ${failures}"
  exit 1
fi

pending="$(
  jq -r '
    .[]
    | select(.status == "queued" or .status == "in_progress" or .status == "requested" or .status == "waiting" or .status == "pending")
    | .name
  ' <<< "${runs}"
)"
if [ -n "${pending}" ]; then
  echo "::error::CI checks are still pending for commit ${sha}: ${pending}"
  exit 1
fi

success="$(
  jq -r '
    .[]
    | select(.status == "completed" and .conclusion == "success")
    | .name
  ' <<< "${runs}"
)"
if [ -z "${success}" ]; then
  echo "::error::No successful completed CI checks found for commit ${sha}."
  exit 1
fi

echo "CI checks passed for commit ${sha}:"
printf '%s\n' "${success}"
