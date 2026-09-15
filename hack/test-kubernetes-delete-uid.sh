#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/kubernetes-delete-uid.XXXXXX")
trap 'rm -rf -- "$fixture"' EXIT HUP INT TERM

cat >"$fixture/kubectl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [ "${3:-}" = proxy ]; then
	while :; do sleep 1; done
fi
exit 2
EOF
chmod +x "$fixture/kubectl"

cat >"$fixture/curl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
body=
request=
for arg in "$@"; do
	case "$arg" in
		--data) data_next=true ;;
		--request) request_next=true ;;
		*)
			if [ "${data_next:-false}" = true ]; then body=$arg; data_next=false; fi
			if [ "${request_next:-false}" = true ]; then request=$arg; request_next=false; fi
			;;
	esac
done
if [ "$request" != DELETE ]; then
	exit 0
fi
printf '%s\n' "$body" >"${DELETE_BODY:?}"
case "${DELETE_MODE:-same}" in
same) exit 0 ;;
replacement) printf '%s\n' replacement >"${RESOURCE_STATE:?}"; exit 1 ;;
*) exit 2 ;;
esac
EOF
chmod +x "$fixture/curl"

cat >"$fixture/run.sh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
source "$1"
PATH="$2:$PATH" KUBECTL_BIN=kubectl KUBECTL_PROXY_PORT=18081 DELETE_BODY="$3" \
  RESOURCE_STATE="${RESOURCE_STATE:?}" \
  kubernetes_delete_uid kubeconfig /api/v1/namespaces/proof/pods/fixture uid-original
EOF
chmod +x "$fixture/run.sh"

RESOURCE_STATE="$fixture/same-resource" DELETE_BODY="$fixture/same.json" "$fixture/run.sh" "$root/hack/kubernetes-delete-uid.sh" "$fixture" "$fixture/same.json"
jq -e '.preconditions.uid == "uid-original" and .kind == "DeleteOptions"' "$fixture/same.json" >/dev/null

if DELETE_MODE=replacement DELETE_BODY="$fixture/replacement.json" \
	RESOURCE_STATE="$fixture/replacement-resource" \
	"$fixture/run.sh" "$root/hack/kubernetes-delete-uid.sh" "$fixture" "$fixture/replacement.json"; then
	printf '%s\n' 'replacement unexpectedly passed the UID precondition' >&2
	exit 1
fi
jq -e '.preconditions.uid == "uid-original"' "$fixture/replacement.json" >/dev/null
[ "$(cat "$fixture/replacement-resource")" = replacement ]
printf '%s\n' 'Kubernetes UID-precondition delete behavior passed'
