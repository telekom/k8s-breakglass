#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)

# Exercise the selected-pod admission contract against API-shaped JSON. The
# API may omit false-valued hostNetwork, but must still reject host networking
# and runtime socket mounts.
command -v jq >/dev/null 2>&1 || {
	printf '%s\n' 'jq is required for selected-pod admission contract checks' >&2
	exit 1
}
admitted_job=$(jq -n '{spec:{template:{spec:{hostPID:true,automountServiceAccountToken:false,volumes:[{name:"evidence",emptyDir:{}}],initContainers:[{securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}},volumeMounts:[{mountPath:"/work"}]}],containers:[{securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"],add:["SYS_ADMIN","SYS_PTRACE","NET_RAW"]}},volumeMounts:[{mountPath:"/work"}]},{securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}},volumeMounts:[{mountPath:"/work"}]}]}}}}')
selected_job_filter='(.spec.template.spec.hostPID == true) and
((.spec.template.spec.hostNetwork // false) == false) and
(.spec.template.spec.automountServiceAccountToken == false) and
(.spec.template.spec.volumes | length == 1 and .[0].emptyDir != null and all(.[]; (.hostPath // null) == null)) and
(.spec.template.spec.initContainers | length == 1) and
(.spec.template.spec.containers | length == 2) and
(.spec.template.spec.initContainers[0].securityContext.allowPrivilegeEscalation == false) and
(.spec.template.spec.initContainers[0].securityContext.capabilities.drop == ["ALL"]) and
(.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation == false) and
(.spec.template.spec.containers[0].securityContext.capabilities.drop == ["ALL"]) and
(.spec.template.spec.containers[0].securityContext.capabilities.add == ["SYS_ADMIN", "SYS_PTRACE", "NET_RAW"]) and
(.spec.template.spec.containers[1].securityContext.allowPrivilegeEscalation == false) and
(.spec.template.spec.containers[1].securityContext.capabilities.drop == ["ALL"]) and
all([.spec.template.spec.initContainers[], .spec.template.spec.containers[]][]; all(.volumeMounts[]?; (.mountPath == "/work" and (.mountPath | IN("/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock", "/var/run/docker.sock") | not))))'
printf '%s\n' "$admitted_job" | jq -e "$selected_job_filter" >/dev/null
if printf '%s\n' "$admitted_job" | jq '.spec.template.spec.hostNetwork = true' | jq -e "$selected_job_filter" >/dev/null; then
	printf '%s\n' 'selected-pod admission check accepted host networking' >&2
	exit 1
fi
if printf '%s\n' "$admitted_job" | jq '.spec.template.spec.containers[0].volumeMounts[0].mountPath = "/var/run/containerd/containerd.sock"' | jq -e "$selected_job_filter" >/dev/null; then
	printf '%s\n' 'selected-pod admission check accepted a runtime socket mount' >&2
	exit 1
fi

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

cat >"$fixture/ip" <<'EOF'
#!/bin/sh
case "$*" in
  '-o address show') printf '%s\n' '1: lo    inet 127.0.0.1/8 scope host lo' ;;
  '-o route show') printf '%s\n' 'default via 192.0.2.1 dev eth0' ;;
  '-o rule show') printf '%s\n' '0: from all lookup local' ;;
  *) exit 2 ;;
esac
EOF
cat >"$fixture/pwru" <<'EOF'
#!/bin/sh
[ "${1:-}" = --version ] || exit 2
printf '%s\n' 'pwru version v1.0.12'
EOF
chmod +x "$fixture/ip" "$fixture/pwru"

if sh "$root/scripts/net-report" --not-an-option >/dev/null 2>&1; then
	printf '%s\n' 'net-report accepted an unknown option' >&2
	exit 1
fi

wrapped=$(sh "$root/scripts/net-debug" printf '%s' 'wrapper-executed')
test "$wrapped" = 'wrapper-executed'
if PATH=/usr/bin:/bin sh "$root/scripts/net-debug" does-not-exist >/dev/null 2>&1; then
	printf '%s\n' 'net-debug accepted an unknown command' >&2
	exit 1
fi

version=$(NETWORK_DEBUG_VERSION=0.1.0 sh "$root/scripts/net-report" --version)
test "$version" = 'net-report 0.1.0'
intent=$(NETWORK_DEBUG_INTENT=network-diagnostics sh "$root/scripts/net-report" | sed -n '2p')
test "$intent" = 'intent network-diagnostics'

hostile_version=$(printf 'trusted\nSECRET_VERSION')
hostile_intent=$(printf 'network-diagnostics\nSECRET_INTENT')
hostile_report=$(NETWORK_DEBUG_VERSION="$hostile_version" NETWORK_DEBUG_INTENT="$hostile_intent" sh "$root/scripts/net-report")
printf '%s\n' "$hostile_report" | grep -F 'network-debug report unknown' >/dev/null
printf '%s\n' "$hostile_report" | grep -F 'intent unknown' >/dev/null
if printf '%s\n' "$hostile_report" | grep -F 'SECRET_' >/dev/null; then
	printf '%s\n' 'net-report emitted hostile metadata' >&2
	exit 1
fi

# Exercise the report against deterministic command fixtures. These assertions
# validate the public runtime output, not implementation files.
first=$(PATH="$fixture:/usr/bin:/bin" NETWORK_DEBUG_VERSION=test sh "$root/scripts/net-report")
second=$(PATH="$fixture:/usr/bin:/bin" NETWORK_DEBUG_VERSION=test sh "$root/scripts/net-report")
test "$first" = "$second"
printf '%s\n' "$first" | grep -F '1: lo    inet 127.0.0.1/8 scope host lo' >/dev/null
printf '%s\n' "$first" | grep -F 'default via 192.0.2.1 dev eth0' >/dev/null
printf '%s\n' "$first" | grep -F '0: from all lookup local' >/dev/null
printf '%s\n' "$first" | grep -E '^pwru[[:space:]]+pwru v1\.0\.12$' >/dev/null

# The image-owned capture command uses a literal tcpdump argv, bounds every
# caller-controlled value, and emits metadata rather than packet contents.
capture_fixture=$(mktemp -d)
mkdir -p "$capture_fixture/bin" "$capture_fixture/work"
cat >"$capture_fixture/bin/tcpdump" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$FAKE_TCPDUMP_ARGS"
output=''
previous=''
for argument in "$@"; do
    if [ "$previous" = -w ]; then output=$argument; fi
    previous=$argument
done
case "$*" in
    '-d '*) exit 0 ;;
    *' -r '*) printf '%s\n' packet-header packet-header; exit 0 ;;
esac
printf '%s' 'pcap-fixture' >"$output"
exit 0
EOF
chmod +x "$capture_fixture/bin/tcpdump"
cat >"$capture_fixture/bin/sha256sum" <<'EOF'
#!/bin/sh
shasum -a 256 "$@"
EOF
chmod +x "$capture_fixture/bin/sha256sum"
capture_report=$(FAKE_TCPDUMP_ARGS="$capture_fixture/args" NETWORK_DEBUG_WORK_DIR="$capture_fixture/work" \
    PATH="$capture_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" capture \
    --interface eth0 --duration 1 --packets 2 --snaplen 64 --filter 'tcp port 443' --output capture.pcap)
printf '%s\n' "$capture_report" | grep -F 'packet_count 2' >/dev/null
printf '%s\n' "$capture_report" | grep -F 'sha256 ' >/dev/null
grep -F -- '-p -i eth0 -s 64 -c 2' "$capture_fixture/args" >/dev/null
[ -f "$capture_fixture/work/capture.pcap" ]
test -z "$(find "$capture_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"
if NETWORK_DEBUG_WORK_DIR="$capture_fixture/work" PATH="$capture_fixture/bin:/usr/bin:/bin" \
    sh "$root/scripts/net-debug" capture --duration 0 >/dev/null 2>&1; then
    printf '%s\n' 'capture accepted an invalid duration' >&2
    exit 1
fi
if NETWORK_DEBUG_WORK_DIR="$capture_fixture/work" PATH="$capture_fixture/bin:/usr/bin:/bin" \
    sh "$root/scripts/net-debug" capture --interface 'eth0/escape' >/dev/null 2>&1; then
    printf '%s\n' 'capture accepted an unsafe interface' >&2
    exit 1
fi
if NETWORK_DEBUG_WORK_DIR="$capture_fixture/work" PATH="$capture_fixture/bin:/usr/bin:/bin" \
    sh "$root/scripts/net-debug" capture --output ../escape >/dev/null 2>&1; then
    printf '%s\n' 'capture accepted output traversal' >&2
    exit 1
fi
if NETWORK_DEBUG_WORK_DIR="$capture_fixture/work" PATH="$capture_fixture/bin:/usr/bin:/bin" \
    sh "$root/scripts/net-debug" capture --output capture.pcap >/dev/null 2>&1; then
    printf '%s\n' 'capture overwrote an existing output' >&2
    exit 1
fi
rm -rf "$capture_fixture"

# A destination appearing while tcpdump is running must never be replaced.
capture_fixture=$(mktemp -d)
mkdir -p "$capture_fixture/bin" "$capture_fixture/work"
cat >"$capture_fixture/bin/tcpdump" <<'EOF'
#!/bin/sh
set -eu
output=''
previous=''
for argument in "$@"; do
    if [ "$previous" = -w ]; then output=$argument; fi
    previous=$argument
done
case "$*" in
    '-d '*) exit 0 ;;
    *' -r '*) printf '%s\n' packet-header; exit 0 ;;
esac
: >"$FAKE_TCPDUMP_STARTED"
sleep 2
printf '%s' pcap-fixture >"$output"
EOF
chmod +x "$capture_fixture/bin/tcpdump"
race_work=$(mktemp -d)
sentinel="$race_work/sentinel"
printf '%s\n' protected >"$sentinel"
FAKE_TCPDUMP_STARTED="$capture_fixture/started" FAKE_TCPDUMP_ARGS="$capture_fixture/race-args" \
    NETWORK_DEBUG_WORK_DIR="$race_work" PATH="$capture_fixture/bin:/usr/bin:/bin" \
    sh "$root/scripts/net-debug" capture --duration 3 --output race.pcap >/dev/null 2>&1 &
capture_pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -f "$capture_fixture/started" ] && break
    sleep 0.1
done
ln -s "$sentinel" "$race_work/race.pcap"
if wait "$capture_pid"; then
    printf '%s\n' 'capture replaced a concurrently-created destination' >&2
    exit 1
fi
test "$(sed -n '1p' "$sentinel")" = protected
test -z "$(find "$race_work" -maxdepth 1 -name '.net-debug.*' -print -quit)"
rm -rf "$race_work" "$capture_fixture"

# Actual carriage returns, not only the literal characters '\\r', are rejected.
capture_fixture=$(mktemp -d)
mkdir -p "$capture_fixture/bin" "$capture_fixture/work"
cat >"$capture_fixture/bin/tcpdump" <<'EOF'
#!/bin/sh
set -eu
output=''
previous=''
for argument in "$@"; do
    if [ "$previous" = -w ]; then output=$argument; fi
    previous=$argument
done
case "$*" in
    '-d '*) exit 0 ;;
    *' -r '*) printf '%s\n' packet-header; exit 0 ;;
esac
printf '%s' pcap-fixture >"$output"
EOF
chmod +x "$capture_fixture/bin/tcpdump"
actual_cr=$(printf 'tcp port 443\r')
if NETWORK_DEBUG_WORK_DIR="$capture_fixture/work" PATH="$capture_fixture/bin:/usr/bin:/bin" \
    sh "$root/scripts/net-debug" capture --filter "$actual_cr" >/dev/null 2>&1; then
    printf '%s\n' 'capture accepted a carriage return in its filter' >&2
    exit 1
fi
test -z "$(find "$capture_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"
rm -rf "$capture_fixture"

# Trace refuses an incomplete kernel/capability environment before invoking
# pwru. This proves the fail-closed boundary without needing BPF on the test
# runner.
if NETWORK_DEBUG_WORK_DIR=/tmp sh "$root/scripts/net-debug" trace >/dev/null 2>&1; then
    printf '%s\n' 'trace accepted an unavailable host prerequisite' >&2
    exit 1
fi

# Trace accepts exactly the approved host-trace capability set (without
# NET_RAW), and fails closed when any required capability is absent.
trace_fixture=$(mktemp -d)
mkdir -p "$trace_fixture/debug" "$trace_fixture/trace" "$trace_fixture/security" "$trace_fixture/bin" "$trace_fixture/work"
: >"$trace_fixture/security/lsm"
{
    printf '1 1 0:1 / %s rw - tmpfs tmpfs rw\n' "$trace_fixture/debug"
    printf '2 2 0:2 / %s rw - tmpfs tmpfs rw\n' "$trace_fixture/trace"
    printf '3 3 0:3 / %s rw - tmpfs tmpfs rw\n' "$trace_fixture/security"
} >"$trace_fixture/mountinfo"
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
case "$*" in
	*'--backend kprobe'*) ;;
	*) exit 2 ;;
esac
printf '%s\n' trace-event
EOF
chmod +x "$trace_fixture/bin/pwru"
cat >"$trace_fixture/bin/readlink" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
	/proc/self/ns/net|/proc/1/ns/net) printf '%s\n' 'net:[4026531993]' ;;
	*) exec /usr/bin/readlink "$@" ;;
esac
EOF
chmod +x "$trace_fixture/bin/readlink"
if [ "$(uname -s)" = Linux ]; then
for required_cap_hex in c001001000 c001000000 c000001000 8001001000 4001001000; do
    printf 'CapEff: %s\n' "$required_cap_hex" >"$trace_fixture/status"
    if NETWORK_DEBUG_WORK_DIR="$trace_fixture/work" \
        NETWORK_DEBUG_BTF_PATH="$trace_fixture/status" NETWORK_DEBUG_DEBUGFS_PATH="$trace_fixture/debug" \
        NETWORK_DEBUG_TRACEFS_PATH="$trace_fixture/trace" NETWORK_DEBUG_SECURITYFS_PATH="$trace_fixture/security" \
        NETWORK_DEBUG_MOUNTINFO_PATH="$trace_fixture/mountinfo" NETWORK_DEBUG_CAPABILITY_FILE="$trace_fixture/status" \
        PATH="$trace_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" trace --duration 1 --events 1 >/dev/null 2>&1; then
        if [ "$required_cap_hex" != c001001000 ]; then
            printf '%s\n' "trace accepted missing capability in $required_cap_hex" >&2
            exit 1
        fi
        test -f "$trace_fixture/work/trace.log"
        test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"
    elif [ "$required_cap_hex" = c001001000 ]; then
        printf '%s\n' 'trace rejected approved capability set' >&2
        exit 1
    fi
done
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
trap '' INT TERM
while :; do
	printf '%s\n' trace-event
	sleep 1
done
EOF
chmod +x "$trace_fixture/bin/pwru"
printf 'CapEff: c001001000\n' >"$trace_fixture/status"
if NETWORK_DEBUG_WORK_DIR="$trace_fixture/work" \
	NETWORK_DEBUG_BTF_PATH="$trace_fixture/status" NETWORK_DEBUG_DEBUGFS_PATH="$trace_fixture/debug" \
	NETWORK_DEBUG_TRACEFS_PATH="$trace_fixture/trace" NETWORK_DEBUG_SECURITYFS_PATH="$trace_fixture/security" \
	NETWORK_DEBUG_MOUNTINFO_PATH="$trace_fixture/mountinfo" NETWORK_DEBUG_CAPABILITY_FILE="$trace_fixture/status" \
	NETWORK_DEBUG_PWRU_STOP_TIMEOUT_SECONDS=1 NETWORK_DEBUG_PWRU_STOP_SETTLE_SECONDS=1 \
	PATH="$trace_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" trace --duration 1 --events 1 >/dev/null 2>&1; then
	printf '%s\n' 'trace unexpectedly succeeded when pwru ignored stop signals' >&2
	exit 1
fi
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"
else
	printf '%s\n' 'skipping Linux-only trace success fixture on non-Linux host' >&2
fi
rm -rf "$trace_fixture"
echo 'network-debug image checks passed'
