#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: CC0-1.0

# A small, deliberately dependency-light verifier used by the PR-management
# prompt.  It verifies *captured GitHub API evidence*; network collection and
# mutations stay in the prompt so an operator can inspect the evidence before
# changing a pull request.
set -euo pipefail

fail() {
  printf 'pr-gate-contract: %s\n' "$*" >&2
  exit 1
}

require_file() {
  test -f "$1" || fail "missing file: $1"
}

require_jq() {
  command -v jq >/dev/null 2>&1 || fail "jq is required"
}

parse_pr_url() {
  test "$#" = 1 || fail "usage: parse-pr-url HTTPS_PR_URL"
  command -v ruby >/dev/null 2>&1 || fail "ruby is required"
  ruby -r uri -e '
    raw = ARGV.fetch(0)
    uri = URI.parse(raw)
    abort "PR URL must use HTTPS" unless uri.is_a?(URI::HTTPS)
    authority = raw[/\Ahttps:\/\/([^\/]+)/i, 1]
    # URI#port normalizes an explicit :443 to the HTTPS default. The gate
    # promises a host-only HTTPS endpoint, so inspect the original authority
    # as well and reject every explicit port, including :443.
    abort "PR URL must not contain an explicit port" unless authority &&
      authority.casecmp?(uri.host.to_s)
    abort "PR URL must not contain credentials, a port, query, or fragment" unless
      uri.userinfo.nil? && uri.port == 443 && uri.query.nil? && uri.fragment.nil?
    segments = uri.path.split("/").reject(&:empty?)
    abort "PR URL must be /OWNER/REPOSITORY/pull/NUMBER" unless
      segments.length == 4 && segments[2] == "pull" && segments[3].match?(/\A[1-9][0-9]*\z/)
    owner, repo = segments.first(2)
    valid = /\A[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?\z/
    abort "invalid repository path" unless owner.match?(valid) && repo.match?(valid)
    abort "invalid GitHub host" unless uri.host && uri.host.match?(/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/i)
    puts [uri.host.downcase, "#{owner}/#{repo}", segments[3]].join("\t")
  ' "$1" || fail "invalid pull-request URL"
}

normalize_branch_protection_http() {
  test "$#" = 2 || fail "usage: normalize-branch-protection-http HTTP_RESPONSE_FILE OUTPUT_JSON"
  require_file "$1"
  command -v ruby >/dev/null 2>&1 || fail "ruby is required"
  ruby -r json -r time -e '
    raw = File.binread(ARGV.fetch(0)).gsub("\r\n", "\n")
    blocks = raw.split(/\n\n/, -1)
    header_indexes = blocks.each_index.select { |index| blocks[index].start_with?("HTTP/") }
    abort "missing HTTP response headers" if header_indexes.empty?
    header_index = header_indexes.last
    header_lines = blocks.fetch(header_index).lines.map(&:strip)
    status = header_lines.shift.to_s
    code = status[/\AHTTP\/\S+\s+(\d{3})\b/, 1]
    abort "malformed HTTP status" unless code
    headers = Hash.new { |hash, key| hash[key] = [] }
    header_lines.each do |line|
      name, value = line.split(":", 2)
      abort "malformed HTTP header" unless name && value
      headers[name.downcase] << value.strip
    end
    body = blocks[(header_index + 1)..].join("\n\n")
    case code
    when "200"
      parsed = JSON.parse(body)
      abort "branch-protection response is not an object" unless parsed.is_a?(Hash)
      File.write(ARGV.fetch(1), JSON.generate(parsed) + "\n")
    when "404"
      dates = headers.fetch("date", [])
      abort "404 missing/ambiguous Date header" unless dates.length == 1
      Time.httpdate(dates.fetch(0))
      request_ids = headers.fetch("x-github-request-id", [])
      abort "404 missing/ambiguous GitHub request ID" unless request_ids.length == 1 &&
        request_ids.fetch(0).match?(/\A[A-Za-z0-9:_-]+\z/)
      content_types = headers.fetch("content-type", [])
      abort "404 missing/ambiguous JSON content type" unless content_types.length == 1 &&
        content_types.fetch(0).match?(/\Aapplication\/json(?:\s*;.*)?\z/i)
      parsed = JSON.parse(body)
      abort "404 error is not an object" unless parsed.is_a?(Hash)
      abort "unexpected 404 message" unless parsed["message"] == "Branch not protected"
      abort "missing 404 documentation URL" unless parsed["documentation_url"].is_a?(String) &&
        parsed["documentation_url"].match?(%r{\Ahttps://docs\.github\.com/})
      abort "unexpected 404 status" unless parsed["status"] == "404" || parsed["status"] == 404
      # The authenticated, GitHub-shaped 404 conclusively says classic branch
      # protection is absent. No other error is normalized as an empty policy.
      File.write(ARGV.fetch(1), "{}\n")
    else
      abort "branch-protection request returned HTTP #{code}"
    end
  ' "$1" "$2" || fail "could not normalize authenticated branch-protection response"
}

manifest_evidence() {
  test "$#" = 2 || fail "usage: manifest-evidence SNAPSHOT_DIRECTORY OUTPUT_FILE"
  test -d "$1" || fail "missing snapshot directory: $1"
  command -v ruby >/dev/null 2>&1 || fail "ruby is required"
  ruby -r digest -r json -e '
    root = File.realpath(ARGV.fetch(0))
    output = File.expand_path(ARGV.fetch(1))
    abort "manifest output must be directly inside its snapshot" unless
      File.realpath(File.dirname(output)) == root

    def canonical_json(value)
      case value
      when Hash
        "{" + value.keys.sort.map { |key|
          JSON.generate(key) + ":" + canonical_json(value.fetch(key))
        }.join(",") + "}"
      when Array
        "[" + value.map { |item| canonical_json(item) }.join(",") + "]"
      else
        JSON.generate(value)
      end
    end

    entries = Dir.glob(File.join(root, "**", "*"), File::FNM_DOTMATCH)
      .select { |path| File.file?(path) }
      .reject { |path| File.expand_path(path) == output }
      .map do |path|
        relative = path.delete_prefix(root + File::SEPARATOR)
        evidence = if File.extname(path) == ".json"
          begin
            canonical_json(JSON.parse(File.binread(path)))
          rescue JSON::ParserError
            abort "invalid JSON evidence: #{relative}"
          end
        else
          "sha256:" + Digest::SHA256.file(path).hexdigest
        end
        [relative, evidence]
      end
    File.binwrite(output, entries.sort_by(&:first).map { |relative, evidence|
      "#{relative}\t#{evidence}\n"
    }.join)
  ' "$1" "$2" || fail "could not create complete evidence manifest"
}

request_date() {
  test "$#" = 1 || fail "usage: request-date HTTP_RESPONSE_FILE"
  require_file "$1"
  command -v ruby >/dev/null 2>&1 || fail "ruby is required"
  ruby -e '
    raw = File.binread(ARGV.fetch(0)).gsub("\r\n", "\n")
    blocks = raw.split(/\n\n/).select { |block| block.start_with?("HTTP/") }
    abort "missing HTTP response headers" if blocks.empty?
    final = blocks.last.lines.map(&:strip)
    status = final.shift
    abort "non-successful review-request response" unless status.match?(/\AHTTP\/\S+ 2\d\d\b/)
    dates = final.grep(/\Adate:\s*/i).map { |line| line.sub(/\Adate:\s*/i, "") }
    abort "missing or ambiguous Date header" unless dates.length == 1
    value = dates.fetch(0)
    abort "invalid HTTP Date" unless value.match?(/\A(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), /)
    puts value
  ' "$1" || fail "ambiguous GitHub review-request Date"
}

request_date_to_ns() {
  test "$#" = 1 || fail "usage: request-date-to-ns HTTP_RESPONSE_FILE"
  local value
  value="$(request_date "$1")"
  ruby -r time -e '
    parsed = Time.httpdate(ARGV.fetch(0)).utc
    abort "non-UTC HTTP Date" unless parsed.utc?
    puts (parsed.to_r * 1_000_000_000).to_i
  ' "$value" || fail "ambiguous GitHub review-request Date"
}

review_timestamp_to_ns() {
  test "$#" = 1 || fail "usage: review-timestamp-to-ns RFC3339_UTC_TIMESTAMP"
  command -v ruby >/dev/null 2>&1 || fail "ruby is required"
  ruby -r time -e '
    value = ARGV.fetch(0)
    abort "invalid RFC3339 timestamp" unless value.match?(/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z\z/)
    parsed = Time.iso8601(value).utc
    abort "non-UTC review timestamp" unless parsed.utc?
    puts (parsed.to_r * 1_000_000_000).to_i
  ' "$1" || fail "invalid formal-review submittedAt"
}

verify_review_freshness() {
  test "$#" = 2 || fail "usage: verify-review-freshness HTTP_RESPONSE_FILE RFC3339_UTC_TIMESTAMP"
  local request_ns review_ns earliest_safe_ns
  request_ns="$(request_date_to_ns "$1")"
  review_ns="$(review_timestamp_to_ns "$2")"
  earliest_safe_ns=$((request_ns + 1000000000))
  # HTTP Date has one-second precision. A review stamped in that same second
  # may have happened before the API response was generated, even when it has
  # fractional seconds. The next whole second is the first provable boundary.
  test "$review_ns" -ge "$earliest_safe_ns" ||
    fail "formal review is not provably after GitHub review-request completion"
}

verify_created_draft() {
  test "$#" = 6 || fail "usage: verify-created-draft PR_JSON REPOSITORY HEAD_REF HEAD_OID BASE_REF BASE_OID"
  local pr_json="$1" repository="$2" head_ref="$3" head_oid="$4" base_ref="$5" base_oid="$6"
  require_jq
  require_file "$pr_json"
  jq -e --arg repository "$repository" --arg headRef "$head_ref" --arg headOid "$head_oid" \
    --arg baseRef "$base_ref" --arg baseOid "$base_oid" '
    type == "object" and .isDraft == true and
    (.headRepository | type) == "object" and .headRepository.nameWithOwner == $repository and
    .headRefName == $headRef and .headRefOid == $headOid and
    (.baseRepository | type) == "object" and .baseRepository.nameWithOwner == $repository and
    .baseRefName == $baseRef and .baseRefOid == $baseOid
  ' "$pr_json" >/dev/null || fail "created draft does not match the verified source/base repository, ref, and OID"
}

inventory_policy() {
  test "$#" = 6 || fail "usage: inventory-policy HOST REPOSITORY BASE_REF EFFECTIVE_JSON PROTECTION_JSON OUTPUT_JSON"
  local host="$1" repository="$2" base_ref="$3" effective="$4" protection="$5" output="$6"
  require_jq
  require_file "$effective"
  require_file "$protection"

  jq -n -e --arg host "$host" --arg repository "$repository" --arg baseRef "$base_ref" \
    --slurpfile effective "$effective" --slurpfile protection "$protection" '
    def rules:
      # `gh api --paginate --slurp` writes one array per API page, wrapped in
      # a single JSON array. Keep every page: a required rule may be on a
      # later page rather than the first one.
      if ($effective | length) == 1 and ($effective[0] | type) == "array" and
           all($effective[0][]; type == "array") then
        [ $effective[0][] | .[] ]
      else error("malformed paginated effective-rules response") end;
    def protection: $protection[0];
    def nonempty_string: type == "string" and length > 0;
    def json_integer: type == "number" and floor == .;
    def nonempty_restrictions:
      [.users[], .teams[], .apps[]] | length > 0;
    # Rulesets call this provider identifier `integration_id`; classic branch
    # protection calls it `app_id`. Neither `null` nor -1 binds a check to an
    # exact GitHub App, so this gate deliberately does not accept either.
    def valid_ruleset_required_check:
      type == "object" and (.context | nonempty_string) and
      (.integration_id | json_integer) and .integration_id > 0;
    def valid_classic_required_check:
      type == "object" and (.context | nonempty_string) and
      (.app_id | json_integer) and .app_id > 0;
    def valid_workflow:
      type == "object" and (.repository_id | json_integer) and .repository_id > 0 and
      (.path | nonempty_string) and
      ((has("ref") | not) or (.ref | nonempty_string)) and
      (.sha | type) == "string" and (.sha | test("^[0-9a-fA-F]{40}$"));
    def valid_code_scanning_tool:
      type == "object" and (.tool | nonempty_string) and
      (.alerts_threshold | IN("none", "errors", "errors_and_warnings", "all")) and
      (.security_alerts_threshold |
       IN("none", "critical", "high_or_higher", "medium_or_higher", "all"));
    def valid_actor_lists:
      type == "object" and (.users | type) == "array" and
      (.teams | type) == "array" and (.apps | type) == "array";
    def valid_pull_request_rule:
      (.parameters | type) == "object" and
      (.parameters.dismiss_stale_reviews_on_push | type) == "boolean" and
      (.parameters.require_code_owner_review | type) == "boolean" and
      (.parameters.require_last_push_approval | type) == "boolean" and
      (.parameters.required_approving_review_count | json_integer) and
      .parameters.required_approving_review_count >= 0 and
      (.parameters.required_review_thread_resolution | type) == "boolean" and
      ((.parameters.dismissal_restriction == null) or
       ((.parameters.dismissal_restriction | type) == "object" and
        (.parameters.dismissal_restriction.enabled | type) == "boolean" and
        (.parameters.dismissal_restriction.allowed_actors | type) == "array" and
        all(.parameters.dismissal_restriction.allowed_actors[];
          (.id | json_integer) and .id > 0 and
          (.type | IN("User", "Team", "IntegrationInstallation", "RepositoryRole"))))) and
      ((.parameters.allowed_merge_methods == null) or
       ((.parameters.allowed_merge_methods | type) == "array" and
        (.parameters.allowed_merge_methods | length) > 0 and
        all(.parameters.allowed_merge_methods[]; IN("merge", "squash", "rebase")))) and
      ((.parameters.required_reviewers == null) or
       ((.parameters.required_reviewers | type) == "array" and
        all(.parameters.required_reviewers[];
          type == "object" and (.file_patterns | type) == "array" and
          all(.file_patterns[]; nonempty_string) and
          (.minimum_approvals | json_integer) and .minimum_approvals >= 0 and
          (.reviewer | type) == "object" and (.reviewer.id | json_integer) and
          .reviewer.id > 0 and .reviewer.type == "Team")));
    def valid_classic_pull_request_reviews:
      type == "object" and
      (.dismissal_restrictions | valid_actor_lists) and
      (.dismiss_stale_reviews | type) == "boolean" and
      (.require_code_owner_reviews | type) == "boolean" and
      (.required_approving_review_count | json_integer) and
      .required_approving_review_count >= 0 and
      (.require_last_push_approval | type) == "boolean" and
      ((.bypass_pull_request_allowances == null) or
       (.bypass_pull_request_allowances | valid_actor_lists));
    def valid_classic_status_checks:
      type == "object" and (.strict | type) == "boolean" and
      (.contexts | type) == "array" and all(.contexts[]; nonempty_string) and
      (.checks | type) == "array" and all(.checks[]; valid_classic_required_check) and
      ((.contexts | length) + (.checks | length)) > 0;
    def valid_known_ruleset_rule:
      type == "object" and (.type | nonempty_string) and
      (if .type == "required_status_checks" then
         (.parameters | type) == "object" and
         (.parameters.strict_required_status_checks_policy | type) == "boolean" and
         ((.parameters.do_not_enforce_on_create == null) or
          (.parameters.do_not_enforce_on_create | type) == "boolean") and
         (.parameters.required_status_checks | type) == "array" and
         (.parameters.required_status_checks | length) > 0 and
         all(.parameters.required_status_checks[]; valid_ruleset_required_check)
       elif .type == "pull_request" then
         valid_pull_request_rule
       elif .type == "workflows" then
         (.parameters.workflows | type) == "array" and
         (.parameters.workflows | length) > 0 and
         all(.parameters.workflows[]; valid_workflow)
       elif .type == "code_scanning" then
         (.parameters.code_scanning_tools | type) == "array" and
         (.parameters.code_scanning_tools | length) > 0 and
         all(.parameters.code_scanning_tools[]; valid_code_scanning_tool)
       elif .type == "required_deployments" then
         (.parameters | type) == "object" and
         (.parameters.required_deployment_environments | type) == "array" and
         (.parameters.required_deployment_environments | length) > 0 and
         all(.parameters.required_deployment_environments[]; nonempty_string)
       elif .type == "required_signatures" then
         ((has("parameters") | not) or .parameters == null or
          ((.parameters | type) == "object" and (.parameters | length) == 0))
       else false end);
    def valid_classic_enabled_field($field):
      (protection[$field] == null) or
      ((protection[$field] | type) == "object" and
       (protection[$field].enabled | type) == "boolean");
    def known_classic_fields:
      ["url", "enabled", "required_status_checks", "required_pull_request_reviews",
       "required_conversation_resolution", "required_signatures", "required_commit_signatures",
       "required_linear_history", "enforce_admins", "allow_force_pushes", "allow_deletions",
       "lock_branch", "allow_fork_syncing", "block_creations", "restrictions"];
    def valid_classic_protection:
      (protection | type) == "object" and
      ((protection.required_status_checks == null) or
       (protection.required_status_checks | valid_classic_status_checks)) and
      ((protection.required_pull_request_reviews == null) or
       (protection.required_pull_request_reviews | valid_classic_pull_request_reviews)) and
      ((protection.required_conversation_resolution == null) or
       valid_classic_enabled_field("required_conversation_resolution")) and
      valid_classic_enabled_field("required_signatures") and
      valid_classic_enabled_field("required_commit_signatures") and
      valid_classic_enabled_field("required_linear_history") and
      valid_classic_enabled_field("enforce_admins") and
      valid_classic_enabled_field("allow_force_pushes") and
      valid_classic_enabled_field("allow_deletions") and
      valid_classic_enabled_field("lock_branch") and
      valid_classic_enabled_field("allow_fork_syncing") and
      valid_classic_enabled_field("block_creations") and
      ((protection.restrictions == null) or
       (protection.restrictions | valid_actor_lists)) and
      ([protection | to_entries[] |
        select(.key as $key | known_classic_fields | index($key) | not) |
        select(.value != null)] | length) == 0;
    def has_classic_status_checks:
      (protection.required_status_checks | type) == "object" and
      ((protection.required_status_checks.checks | length) > 0 or
       (protection.required_status_checks.contexts | length) > 0);
    def classic_rules:
      [
        if has_classic_status_checks then
          {type: "required_status_checks", source: "classic_branch_protection",
           parameters: protection.required_status_checks}
        else empty end,
        if (protection.required_pull_request_reviews | type) == "object" then
          {type: "pull_request", source: "classic_branch_protection",
           parameters: protection.required_pull_request_reviews}
        else empty end,
        if protection.required_conversation_resolution.enabled == true then
          {type: "pull_request", source: "classic_branch_protection",
           parameters: protection.required_conversation_resolution}
        else empty end,
        if protection.required_signatures.enabled == true or
           protection.required_commit_signatures.enabled == true then
          {type: "required_signatures", source: "classic_branch_protection",
           parameters: (protection.required_signatures // protection.required_commit_signatures)}
        else empty end,
        if protection.required_linear_history.enabled == true then
          {type: "required_linear_history", source: "classic_branch_protection",
           parameters: protection.required_linear_history}
        else empty end,
        if protection.enforce_admins.enabled == true then
          {type: "enforce_admins", source: "classic_branch_protection",
           parameters: protection.enforce_admins}
        else empty end,
        if protection.allow_force_pushes.enabled == true then
          {type: "allow_force_pushes", source: "classic_branch_protection",
           parameters: protection.allow_force_pushes}
        else empty end,
        if protection.allow_deletions.enabled == true then
          {type: "allow_deletions", source: "classic_branch_protection",
           parameters: protection.allow_deletions}
        else empty end,
        if protection.lock_branch.enabled == true then
          {type: "lock_branch", source: "classic_branch_protection",
           parameters: protection.lock_branch}
        else empty end,
        if protection.allow_fork_syncing.enabled == true then
          {type: "allow_fork_syncing", source: "classic_branch_protection",
           parameters: protection.allow_fork_syncing}
        else empty end,
        if protection.block_creations.enabled == true then
          {type: "block_creations", source: "classic_branch_protection",
           parameters: protection.block_creations}
        else empty end,
        if (protection.restrictions | type) == "object" and
           (protection.restrictions | nonempty_restrictions) then
          {type: "restrictions", source: "classic_branch_protection",
           parameters: protection.restrictions}
        else empty end
      ];
    def rule_checks($all_rules):
      [$all_rules[] | select(.type == "required_status_checks") |
       (.parameters.required_status_checks // [])[]? |
       {context: (.context // ""), appId: (.integration_id // .app_id)}];
    def protection_checks:
      [((protection.required_status_checks.checks // [])[]?) |
       {context: .context, appId: .app_id}];
    def legacy_contexts:
      (protection.required_status_checks.contexts // []) as $contexts |
      ([protection_checks[] | .context]) as $provider_bound |
      [$contexts[] | select($provider_bound | index(.) | not)];
    def supported_type:
      . == "required_status_checks" or . == "pull_request" or
      . == "required_signatures" or . == "workflows" or
      . == "required_deployments" or . == "code_scanning";
    rules as $rules |
    classic_rules as $classic_rules |
    ($rules + $classic_rules) as $all_rules |
    (rule_checks($all_rules) + protection_checks) as $checks |
    ([ $checks[] | .context ] | unique) as $names |
    (legacy_contexts) as $legacy |
    ([ $all_rules[] | select(.type | supported_type | not) |
       {type, source, parameters} ]) as $unsupported |
    if ($host | test("\\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\\z"; "i") | not) then
      error("invalid GitHub host")
    elif ($repository | test("\\A[^/ ]+/[^/ ]+\\z") | not) then
      error("invalid repository")
    elif ($all_rules | type) != "array" or ($all_rules | length) == 0 then
      error("no active ruleset or classic branch-protection requirement; refusing a no-op policy")
    elif valid_classic_protection | not then
      error("malformed classic branch-protection schema")
    elif any($rules[]; valid_known_ruleset_rule | not) then
      error("malformed known ruleset schema or parameters")
    elif ($unsupported | length) != 0 then
      error("unsupported active rule(s): " + ($unsupported | tojson) +
            "; extend the verifier for these exact type/parameters or remove the rule before using this gate")
    elif any($checks[]; (.context | type) != "string" or .context == "" or
                       (.appId | type) != "number" or .appId <= 0) then
      error("required check lacks an exact GitHub App integration ID")
    elif ($names | length) != ($checks | length) then
      error("duplicate required check context is ambiguous")
    elif ($legacy | length) != 0 then
      error("legacy required status context cannot be bound to a GitHub App; migrate it to a required check run")
    else {
      schema: 2,
      githubHost: $host,
      repository: $repository,
      baseRef: $baseRef,
      effectiveRules: $rules,
      classicBranchProtectionRules: $classic_rules,
      branchProtection: protection,
      requiredCheckRuns: ($checks | sort_by(.context, .appId)),
      mergeStateRequired: true,
      directEvidence: {
        required_status_checks: "exact App-bound check run and exact PR-associated suite",
        pull_request: "GitHub reviewDecision plus zero unresolved review threads",
        required_signatures: "exact PR final GitHub merge-state predicate",
        workflows: "exact PR final GitHub merge-state predicate",
        required_deployments: "exact PR final GitHub merge-state predicate",
        code_scanning: "exact PR final GitHub merge-state predicate"
      },
      legacyStatusPolicy: "reject-required-contexts-without-provider-binding"
    }
    end
  ' >"$output" || fail "could not build exact policy inventory"
}

verify_checks() {
  test "$#" = 7 || fail "usage: verify-checks IDENTITY_JSON INVENTORY_JSON REPOSITORY_JSON RUNS_JSON SUITES_JSON STATUSES_JSON OUTPUT_JSON"
  local identity="$1" inventory="$2" repository="$3" runs="$4" suites="$5" statuses="$6" output="$7"
  require_jq
  local item
  for item in "$identity" "$inventory" "$repository" "$runs" "$suites" "$statuses"; do
    require_file "$item"
  done

  jq -n -e --slurpfile identity "$identity" --slurpfile inventory "$inventory" \
    --slurpfile repository "$repository" --slurpfile runs "$runs" \
    --slurpfile suites "$suites" --slurpfile statuses "$statuses" '
    $identity[0].data.repository.pullRequest as $pr |
    $inventory[0] as $policy |
    $repository[0] as $repo |
    def nonempty_string: type == "string" and length > 0;
    def exact_repo($candidate):
      $candidate.id == $repo.id and
      $candidate.full_name == $repo.full_name and
      $candidate.html_url == $repo.html_url and
      $candidate.url == $repo.url;
    def exact_association($suite):
      [ $suite.pull_requests[]? |
        select(.head.sha == $pr.headRefOid and .head.ref == $pr.headRefName and
               exact_repo(.head.repo) and
               .base.sha == $pr.baseRefOid and .base.ref == $pr.baseRefName and
               exact_repo(.base.repo))
      ] | length == 1;
    def suite_for($run):
      [ $suites[0][] |
        select(.id == $run.check_suite.id and .head_sha == $run.head_sha and
               exact_repo(.repository) and .app.id == $run.app.id and
               exact_association(.))
      ] | length == 1;
    def exact_success($need):
      [ $runs[0][] |
        select((.observedOid == .head_sha) and
               (.head_sha == $pr.headRefOid or .head_sha == ($pr.potentialMergeCommit.oid // $pr.headRefOid)) and
               .name == $need.context and .app.id == $need.appId and
               (.app.owner.login | nonempty_string) and (.app.slug | nonempty_string) and
               .status == "completed" and (.conclusion | ascii_upcase) == "SUCCESS" and suite_for(.))
      ] | length > 0;
    def required_status_names: ($policy.requiredCheckRuns | map(.context));
    if ($policy.schema != 2 or $policy.mergeStateRequired != true) then
      error("unsupported or incomplete policy inventory")
    elif (($policy.repository != $repo.full_name) or (($policy.githubHost | nonempty_string) | not)) then
      error("inventory and captured repository disagree")
    elif (($repo.html_url != ("https://" + $policy.githubHost + "/" + $repo.full_name)) or
          (($repo.url | nonempty_string) | not)) then
      error("repository was not captured from the pinned HTTPS GitHub host")
    elif ($pr.headRepository.nameWithOwner != $repo.full_name or
          $pr.baseRepository.nameWithOwner != $repo.full_name) then
      error("fork or mismatched source/base repository")
    elif ($pr.isDraft != false or $pr.mergeable != "MERGEABLE" or $pr.mergeStateStatus != "CLEAN") then
      error("GitHub does not currently attest that this exact PR is mergeable and policy-clean")
    elif any($policy.requiredCheckRuns[]; exact_success(.) | not) then
      error("a required App-bound check has no successful exact source-head or synthetic-candidate run")
    elif any($statuses[0][]; (.context as $context | required_status_names | index($context)) != null) then
      error("legacy status collides with a required check-run context and cannot be provider-bound safely")
    else {
      schema: 1,
      verified: true,
      acceptedHeads: [$pr.headRefOid, ($pr.potentialMergeCommit.oid // $pr.headRefOid)] | unique,
      repository: $repo.full_name,
      githubHost: $policy.githubHost
    }
    end
  ' >"$output" || fail "required check/provider/suite evidence is invalid"
}

usage() {
  cat >&2 <<'EOF'
usage:
  pr-gate-contract.sh parse-pr-url HTTPS_PR_URL
  pr-gate-contract.sh normalize-branch-protection-http HTTP_RESPONSE_FILE OUTPUT_JSON
  pr-gate-contract.sh manifest-evidence SNAPSHOT_DIRECTORY OUTPUT_FILE
  pr-gate-contract.sh request-date HTTP_RESPONSE_FILE
  pr-gate-contract.sh request-date-to-ns HTTP_RESPONSE_FILE
  pr-gate-contract.sh verify-review-freshness HTTP_RESPONSE_FILE RFC3339_UTC_TIMESTAMP
  pr-gate-contract.sh verify-created-draft PR_JSON REPOSITORY HEAD_REF HEAD_OID BASE_REF BASE_OID
  pr-gate-contract.sh inventory-policy HOST REPOSITORY BASE_REF EFFECTIVE_JSON PROTECTION_JSON OUTPUT_JSON
  pr-gate-contract.sh verify-checks IDENTITY_JSON INVENTORY_JSON REPOSITORY_JSON RUNS_JSON SUITES_JSON STATUSES_JSON OUTPUT_JSON
EOF
  exit 64
}

command="${1-}"
case "$command" in
  parse-pr-url) shift; parse_pr_url "$@" ;;
  normalize-branch-protection-http) shift; normalize_branch_protection_http "$@" ;;
  manifest-evidence) shift; manifest_evidence "$@" ;;
  request-date) shift; request_date "$@" ;;
  request-date-to-ns) shift; request_date_to_ns "$@" ;;
  verify-review-freshness) shift; verify_review_freshness "$@" ;;
  verify-created-draft) shift; verify_created_draft "$@" ;;
  inventory-policy) shift; inventory_policy "$@" ;;
  verify-checks) shift; verify_checks "$@" ;;
  *) usage ;;
esac
