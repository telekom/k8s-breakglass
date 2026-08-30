#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Helpers for GitHub Actions E2E diagnostics. Keep sourced credential-bearing
# values masked and avoid uploading Docker inspect environment fields.

ci_escape_workflow_command_value() {
  local value="$1"
  value="${value//%/%25}"
  value="${value//$'\r'/%0D}"
  value="${value//$'\n'/%0A}"
  printf '%s' "$value"
}

ci_mask_secret_like_e2e_env() {
  local name value

  while IFS= read -r name; do
    case "$name" in
      E2E_* | BREAKGLASS_* | KEYCLOAK_* | MAILHOG_* | PLAYWRIGHT_* | VITE_*)
        case "$name" in
          *SECRET* | *PASSWORD* | *PASS* | *TOKEN* | *PRIVATE* | *CREDENTIAL* | *AUTH_HEADER* | *COOKIE*)
            value="${!name-}"
            if [ -n "$value" ]; then
              printf '::add-mask::%s\n' "$(ci_escape_workflow_command_value "$value")"
            fi
            ;;
        esac
        ;;
    esac
  done < <(compgen -e)
}

ci_print_e2e_env_allowlist() {
  local name
  local allowlist=(
    E2E_TEST
    E2E_NAMESPACE
    E2E_CLUSTER_NAME
    BREAKGLASS_API_URL
    BREAKGLASS_WEBHOOK_URL
    BREAKGLASS_METRICS_URL
    KEYCLOAK_URL
    KEYCLOAK_HOST
    KEYCLOAK_PORT
    KEYCLOAK_REALM
    KEYCLOAK_CLIENT_ID
    KEYCLOAK_ISSUER_HOST
    KEYCLOAK_INTERNAL_URL
    KEYCLOAK_SERVICE_HOSTNAME
    MAILHOG_URL
    MAILHOG_HOST
    MAILHOG_PORT
    MAILHOG_UI_PORT
    PLAYWRIGHT_BASE_URL
    VITE_API_BASE_URL
    VITE_KEYCLOAK_URL
    VITE_KEYCLOAK_REALM
    VITE_KEYCLOAK_CLIENT_ID
  )

  for name in "${allowlist[@]}"; do
    if [ "${!name+x}" = "x" ]; then
      printf '%s=%s\n' "$name" "${!name}"
    fi
  done
}

ci_redacted_docker_inspect() {
  local container="$1"
  local output="$2"

  if command -v jq >/dev/null 2>&1; then
    docker inspect "$container" \
      | jq 'walk(if type == "object" and has("Env") then del(.Env) else . end)' \
      > "$output"
  else
    {
      echo "jq unavailable; full docker inspect omitted to avoid environment disclosure."
      echo "Container: $container"
      echo
      echo "State:"
      docker inspect "$container" --format '{{json .State}}' 2>&1 || true
      echo
      echo "Mounts:"
      docker inspect "$container" --format '{{json .Mounts}}' 2>&1 || true
      echo
      echo "NetworkSettings:"
      docker inspect "$container" --format '{{json .NetworkSettings}}' 2>&1 || true
    } > "$output"
  fi
}

ci_redact_diagnostic_stream() {
  perl -pe '
    if ($in_private_key) {
      $in_private_key = 0 if /-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/i;
      $_ = "";
      next;
    }
    if (/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/i) {
      $in_private_key = 1 unless /-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/i;
      $_ = "-----BEGIN PRIVATE KEY----- [REDACTED]\n";
      next;
    }
	s~^([[:space:]]*(?:authorization|proxy-authorization|cookie|set-cookie|api-key|x-[a-z0-9-]*(?:api-key|token|secret|password|credential|cookie))[[:space:]]*:[[:space:]]*).*$~$1[REDACTED]~ig;
    s~((?:authorization|proxy-authorization)\s*[:=]\s*(?:Bearer|Basic)\s+)[^\s,"}]+~$1[REDACTED]~ig;
    s~("(?:access[_-]?token|refresh[_-]?token|id[_-]?token|subject[_-]?token|actor[_-]?token|auth[_-]?token|bearer[_-]?token|session[_-]?token|token|secret|client[_-]?secret|api[_-]?key|password|passwd|private[_-]?key|credential|credentials|cookie)"\s*:\s*)"(?:\\.|[^"\\])*"~$1"[REDACTED]"~ig;
    s~^([[:space:]]*(?:access[_-]?token|refresh[_-]?token|id[_-]?token|subject[_-]?token|actor[_-]?token|auth[_-]?token|bearer[_-]?token|session[_-]?token|token|secret|client[_-]?secret|api[_-]?key|password|passwd|private[_-]?key|credential|credentials|cookie)[[:space:]]*:[[:space:]]*)(?:"(?:\\.|[^"\\])*"|\047(?:\\.|[^\047\\])*\047|[^#\r\n]*?)([[:space:]]*(?:#.*)?\r?\n?)$~$1[REDACTED]$2~ig;
    s~((?:access[_-]?token|refresh[_-]?token|id[_-]?token|subject[_-]?token|actor[_-]?token|auth[_-]?token|bearer[_-]?token|session[_-]?token|token|secret|client[_-]?secret|api[_-]?key|password|passwd|private[_-]?key|credential|credentials|cookie)\s*=\s*)(?:"(?:\\.|[^"\\])*"|\047(?:\\.|[^\047\\])*\047|[^\s,;]+)~$1[REDACTED]~ig;
    s~[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}~[REDACTED-JWT]~g;
    s~[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}~[REDACTED-EMAIL]~g;
  '
}

ci_write_bounded_redacted_file() {
  local output="$1"
  local max_lines="${2:-2000}"
  local max_bytes="${3:-1048576}"

  mkdir -p "$(dirname "$output")"
	ci_redact_diagnostic_stream \
		| tail -c "$max_bytes" \
		| tail -n "$max_lines" \
		> "$output"
}
