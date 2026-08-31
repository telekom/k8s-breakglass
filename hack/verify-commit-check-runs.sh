#!/usr/bin/env bash

set -euo pipefail

repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
sha="${GITHUB_SHA:?GITHUB_SHA is required}"
current_run_id="${GITHUB_RUN_ID:-}"
ignored_run_ids='[]'

if [ "${IGNORE_RELEASE_WORKFLOW_RUNS:-false}" = true ]; then
  if [ -n "${CHECK_RUNS_JSON:-}" ]; then
    ignored_run_ids="${CHECK_RUN_IGNORED_RUN_IDS_JSON:-[]}"
  else
    ignored_run_ids="$(
      gh api --paginate "repos/${repo}/actions/runs?head_sha=${sha}&per_page=100" --jq '.workflow_runs[]' |
        jq -s -c '[.[] | select(.path == ".github/workflows/release.yml" or (.path == ".github/workflows/utility-release.yml" and .head_branch != "main")) | (.id | tostring)] | unique'
    )"
  fi
fi
jq -e 'type == "array" and all(.[]; type == "string")' <<<"${ignored_run_ids}" >/dev/null || { echo 'invalid ignored workflow run IDs' >&2; exit 1; }
if [ -n "${current_run_id}" ]; then
  ignored_run_ids="$(jq -cn --argjson ids "${ignored_run_ids}" --arg id "${current_run_id}" '$ids + [$id] | unique')"
fi

# shellcheck disable=SC2016 # This is a jq program, not shell interpolation.
filter_ignored_runs='
  def ignored_run_url:
    (.details_url // "") as $details | (.html_url // "") as $html |
    any($ignored_run_ids[]; . as $id |
      ($details | contains("/actions/runs/" + $id + "/")) or
      ($html | contains("/actions/runs/" + $id + "/")));
  map(select(ignored_run_url | not))
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

filtered_runs="$(jq -c --argjson ignored_run_ids "${ignored_run_ids}" "${filter_ignored_runs}" <<< "${all_runs}")"

ignored_count="$(( $(jq 'length' <<< "${all_runs}") - $(jq 'length' <<< "${filtered_runs}") ))"
if [ "${ignored_count}" -gt 0 ]; then
  echo "Ignoring ${ignored_count} check run(s) from release orchestration workflow runs."
fi

runs="$(jq -c "${latest_runs_by_check}" <<< "${filtered_runs}")"
superseded_count="$(( $(jq 'length' <<< "${filtered_runs}") - $(jq 'length' <<< "${runs}") ))"
if [ "${superseded_count}" -gt 0 ]; then
  echo "Ignoring ${superseded_count} superseded check run attempt(s); evaluating latest check run per app/name."
fi

if [ -n "${REQUIRED_CHECKS_JSON:-}" ]; then
  jq -e 'type=="array" and length>0 and all(.[]; type=="string" and length>0) and length==(unique|length)' <<<"${REQUIRED_CHECKS_JSON}" >/dev/null || {
    echo '::error::REQUIRED_CHECKS_JSON must be a non-empty unique string array.'; exit 1;
  }
  required_state="$(jq -c --argjson required "${REQUIRED_CHECKS_JSON}" '
    [$required[] as $name |
      ([.[] | select(.name==$name and .app.slug=="github-actions")] | if length==1 then .[0] else null end) as $run |
      {name:$name, present:($run!=null), status:($run.status//"missing"), conclusion:($run.conclusion//"missing")}]
  ' <<<"${runs}")"
  missing_required="$(jq -r '.[]|select(.present|not)|.name' <<<"${required_state}")"
  [ -z "${missing_required}" ] || { echo "::error::Required CI checks missing for commit ${sha}: ${missing_required}"; exit 1; }
  incomplete_required="$(jq -r '.[]|select(.status!="completed" or .conclusion!="success")|"\(.name): \(.status)/\(.conclusion)"' <<<"${required_state}")"
  [ -z "${incomplete_required}" ] || { echo "::error::Required CI checks are not successful for commit ${sha}: ${incomplete_required}"; exit 1; }
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
