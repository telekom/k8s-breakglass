#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
test_context='startup'

command -v jq >/dev/null 2>&1 || {
	printf '%s\n' 'jq is required for deterministic report checks' >&2
	exit 1
}
fixture=$(mktemp -d)
# shellcheck disable=SC2154 # status is assigned by the EXIT trap at runtime.
trap 'status=$?; if [ "$status" -ne 0 ]; then printf "FAIL: test.sh assertion (%s)\n" "$test_context" >&2; fi; rm -rf "$fixture"; exit "$status"' EXIT HUP INT TERM

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

cat >"$fixture/sed" <<'EOF'
#!/bin/sh
if [ "${1:-}" = '-nE' ]; then
    printf '%s\n' 'unsupported sed ERE flags' >&2
    exit 2
fi
exec /usr/bin/sed "$@"
EOF
chmod +x "$fixture/sed"

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
test_context='capture-basic'
capture_fixture=$(mktemp -d)
mkdir -p "$capture_fixture/bin" "$capture_fixture/work"
cat >"$capture_fixture/bin/tcpdump" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$FAKE_TCPDUMP_ARGS"
if [ -n "${FAKE_TCPDUMP_ARGV:-}" ]; then
    for argument in "$@"; do
        printf '<%s>\n' "$argument" >>"$FAKE_TCPDUMP_ARGV"
    done
fi
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
if [ "$output" = - ]; then
    printf '%s' 'pcap-fixture'
else
    printf '%s' 'pcap-fixture' >"$output"
fi
exit 0
EOF
chmod +x "$capture_fixture/bin/tcpdump"
system_sha256sum=$(command -v sha256sum 2>/dev/null || true)
case "$system_sha256sum" in
    /*) ;;
    *) printf '%s\n' 'system sha256sum is required for capture fixture' >&2; exit 1 ;;
esac
cat >"$capture_fixture/bin/sha256sum" <<EOF
#!/bin/sh
exec "$system_sha256sum" "\$@"
EOF
chmod +x "$capture_fixture/bin/sha256sum"
capture_report=$(FAKE_TCPDUMP_ARGS="$capture_fixture/args" FAKE_TCPDUMP_ARGV="$capture_fixture/argv" NETWORK_DEBUG_WORK_DIR="$capture_fixture/work" \
    PATH="$capture_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" capture \
    --interface eth0 --duration 1 --packets 2 --snaplen 64 --filter 'tcp port 443' --output capture.pcap)
printf '%s\n' "$capture_report" | grep -F 'packet_count 2' >/dev/null
printf '%s\n' "$capture_report" | grep -F 'sha256 ' >/dev/null
grep -F -- '-p -i eth0 -s 64 -c 2' "$capture_fixture/args" >/dev/null
grep -Fx '<tcp port 443>' "$capture_fixture/argv" >/dev/null
if grep -Fx '<"tcp port 443">' "$capture_fixture/argv" >/dev/null; then
    printf '%s\n' 'capture passed literal quotes around its filter argument' >&2
    exit 1
fi
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

# Validation diagnostics describe the configured work directory without
# assuming the default /work mount used by the image.
test_context='capture-work-directory-diagnostic'
capture_fixture=$(mktemp -d)
mkdir -p "$capture_fixture/work"
invalid_output_error=$(NETWORK_DEBUG_WORK_DIR="$capture_fixture/work" \
    sh "$root/scripts/net-debug" capture --output ../escape 2>&1 >/dev/null || true)
test "$invalid_output_error" = 'net-debug: output must be a filename in the work directory'
missing_work_error=$(NETWORK_DEBUG_WORK_DIR="$capture_fixture/missing" \
    sh "$root/scripts/net-debug" capture --output capture.pcap 2>&1 >/dev/null || true)
test "$missing_work_error" = 'net-debug: work directory is not available'
rm -rf "$capture_fixture"

# A destination appearing while tcpdump is running must never be replaced.
test_context='capture-race'
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
if [ "$output" = - ]; then
    printf '%s' pcap-fixture
else
    printf '%s' pcap-fixture >"$output"
fi
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
test_context='capture-filter-carriage-return'
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
if [ "$output" = - ]; then
    printf '%s' pcap-fixture
else
    printf '%s' pcap-fixture >"$output"
fi
EOF
chmod +x "$capture_fixture/bin/tcpdump"
actual_cr=$(printf 'tcp port 443\r')
actual_cr_error=$(NETWORK_DEBUG_WORK_DIR="$capture_fixture/work" PATH="$capture_fixture/bin:/usr/bin:/bin" \
    sh "$root/scripts/net-debug" capture --filter "$actual_cr" 2>&1 >/dev/null || true)
if [ "$actual_cr_error" != 'net-debug: filter must not contain CR or LF' ]; then
    printf '%s\n' 'capture accepted a carriage return in its filter' >&2
    exit 1
fi
test -z "$(find "$capture_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"
rm -rf "$capture_fixture"

# Trace refuses an incomplete kernel/capability environment before invoking
# pwru. This proves the fail-closed boundary without needing BPF on the test
# runner.
test_context='trace-prerequisite-fail-closed'
if NETWORK_DEBUG_WORK_DIR=/tmp sh "$root/scripts/net-debug" trace >/dev/null 2>&1; then
    printf '%s\n' 'trace accepted an unavailable host prerequisite' >&2
    exit 1
fi

# Trace accepts exactly the approved host-trace capability set (without
# NET_RAW), including SYS_PTRACE for the kernel-enforced /proc/1 namespace
# identity check, and fails closed when any required capability is absent.
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
case "$*" in
	*'--output-meta=false'*) ;;
	*) exit 2 ;;
esac
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80'
EOF
chmod +x "$trace_fixture/bin/pwru"
cat >"$trace_fixture/bin/readlink" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
	/proc/self/ns/net) if [ "${TRACE_PRIVATE_NETWORK:-false}" = true ]; then printf '%s\n' 'net:[4026531993]'; else printf '%s\n' 'net:[4026531994]'; fi ;;
	/proc/1/ns/net) if [ "${TRACE_PRIVATE_NETWORK:-false}" = true ]; then printf '%s\n' 'net:[4026531995]'; else printf '%s\n' 'net:[4026531994]'; fi ;;
	/proc/self/ns/mnt) if [ "${TRACE_PRIVATE:-false}" = true ]; then printf '%s\n' 'mnt:[4026531994]'; else printf '%s\n' 'mnt:[4026531994]'; fi ;;
	/proc/1/ns/mnt) if [ "${TRACE_PRIVATE:-false}" = true ]; then printf '%s\n' 'mnt:[4026531994]'; else printf '%s\n' 'mnt:[4026531995]'; fi ;;
	*) exec /usr/bin/readlink "$@" ;;
esac
EOF
chmod +x "$trace_fixture/bin/readlink"
cat >"$trace_fixture/bin/stat" <<'EOF'
#!/bin/sh
set -eu
case "${TRACE_PRIVATE:-false}:$*" in
	true:*'/proc/1/root'*) printf '%s\n' '1:1' ;;
	true:*) printf '%s\n' '1:1' ;;
	false:*'/proc/1/root'*) printf '%s\n' '2:2' ;;
	false:*) printf '%s\n' '1:1' ;;
esac
EOF
chmod +x "$trace_fixture/bin/stat"
cat >"$trace_fixture/bin/setsid" <<'EOF'
#!/bin/sh
exec /usr/bin/setsid "$@"
EOF
chmod +x "$trace_fixture/bin/setsid"
if [ "$(uname -s)" = Linux ]; then
for required_cap_hex in c001081000 c001001000 c001000000 c000001000 8001001000 4001001000; do
    test_context="trace-capability-$required_cap_hex"
    printf 'CapEff: %s\n' "$required_cap_hex" >"$trace_fixture/status"
    if NETWORK_DEBUG_WORK_DIR="$trace_fixture/work" \
        NETWORK_DEBUG_BTF_PATH="$trace_fixture/status" NETWORK_DEBUG_DEBUGFS_PATH="$trace_fixture/debug" \
        NETWORK_DEBUG_TRACEFS_PATH="$trace_fixture/trace" NETWORK_DEBUG_SECURITYFS_PATH="$trace_fixture/security" \
        NETWORK_DEBUG_MOUNTINFO_PATH="$trace_fixture/mountinfo" NETWORK_DEBUG_CAPABILITY_FILE="$trace_fixture/status" \
        PATH="$trace_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" trace --duration 1 --events 1 >/dev/null 2>&1; then
        if [ "$required_cap_hex" != c001081000 ]; then
            printf '%s\n' "trace accepted missing capability in $required_cap_hex" >&2
            exit 1
        fi
        test -f "$trace_fixture/work/trace.log"
        test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"
    elif [ "$required_cap_hex" = c001081000 ]; then
        printf '%s\n' 'trace rejected approved capability set' >&2
        exit 1
    fi
done
test_context='trace-private-network-namespace-rejected'
if TRACE_PRIVATE_NETWORK=true NETWORK_DEBUG_WORK_DIR="$trace_fixture/work" \
	NETWORK_DEBUG_BTF_PATH="$trace_fixture/status" NETWORK_DEBUG_DEBUGFS_PATH="$trace_fixture/debug" \
	NETWORK_DEBUG_TRACEFS_PATH="$trace_fixture/trace" NETWORK_DEBUG_SECURITYFS_PATH="$trace_fixture/security" \
	NETWORK_DEBUG_MOUNTINFO_PATH="$trace_fixture/mountinfo" NETWORK_DEBUG_CAPABILITY_FILE="$trace_fixture/status" \
	PATH="$trace_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" trace --duration 1 --events 1 >/dev/null 2>&1; then
	printf '%s\n' 'trace accepted a private network namespace' >&2
	exit 1
fi
test_context='trace-private-pid-namespace-rejected'
if TRACE_PRIVATE=true NETWORK_DEBUG_WORK_DIR="$trace_fixture/work" \
	NETWORK_DEBUG_BTF_PATH="$trace_fixture/status" NETWORK_DEBUG_DEBUGFS_PATH="$trace_fixture/debug" \
	NETWORK_DEBUG_TRACEFS_PATH="$trace_fixture/trace" NETWORK_DEBUG_SECURITYFS_PATH="$trace_fixture/security" \
	NETWORK_DEBUG_MOUNTINFO_PATH="$trace_fixture/mountinfo" NETWORK_DEBUG_CAPABILITY_FILE="$trace_fixture/status" \
	PATH="$trace_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" trace --duration 1 --events 1 >/dev/null 2>&1; then
	printf '%s\n' 'trace accepted a private PID and mount namespace' >&2
	exit 1
fi
# Full-node visibility options: the kprobe-multi backend needs CAP_SYSLOG to
# read kallsyms, --meta adds the NETNS column, and --all-kmods covers module
# functions. The fixture records the exact pwru argv.
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >"$PWRU_ARGS_FILE"
printf '%s\n' '0xffff 1 <empty>:0 4026533068 0 eth0:3 0x0800 1500 60 10.0.0.1:12345->10.0.0.2:80(tcp) ip_rcv'
EOF
chmod +x "$trace_fixture/bin/pwru"
trace_visibility() {
	NETWORK_DEBUG_WORK_DIR="$trace_fixture/work" PWRU_ARGS_FILE="$trace_fixture/pwru.args" \
		NETWORK_DEBUG_BTF_PATH="$trace_fixture/status" NETWORK_DEBUG_DEBUGFS_PATH="$trace_fixture/debug" \
		NETWORK_DEBUG_TRACEFS_PATH="$trace_fixture/trace" NETWORK_DEBUG_SECURITYFS_PATH="$trace_fixture/security" \
		NETWORK_DEBUG_MOUNTINFO_PATH="$trace_fixture/mountinfo" NETWORK_DEBUG_CAPABILITY_FILE="$trace_fixture/status" \
		PATH="$trace_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" trace --duration 1 --events 1 "$@"
}
test_context='trace-kprobe-multi-requires-syslog'
printf 'CapEff: c001081000\n' >"$trace_fixture/status"
rm -f "$trace_fixture/work/trace.log" "$trace_fixture/pwru.args"
if trace_visibility --backend kprobe-multi >/dev/null 2>"$trace_fixture/syslog-error"; then
	printf '%s\n' 'trace accepted kprobe-multi without CAP_SYSLOG' >&2
	exit 1
fi
grep -F 'SYSLOG' "$trace_fixture/syslog-error" >/dev/null
test ! -e "$trace_fixture/pwru.args"
test_context='trace-unknown-backend-rejected'
if trace_visibility --backend fentry >/dev/null 2>&1; then
	printf '%s\n' 'trace accepted an unknown backend' >&2
	exit 1
fi
test ! -e "$trace_fixture/pwru.args"
test_context='trace-full-visibility-options'
printf 'CapEff: c401081000\n' >"$trace_fixture/status"
trace_visibility --backend kprobe-multi --all-kmods --meta --filter 'host 10.0.0.2' >"$trace_fixture/visibility-summary"
grep -Fx 'backend kprobe-multi' "$trace_fixture/visibility-summary" >/dev/null
case "$(cat "$trace_fixture/pwru.args")" in
	'--backend kprobe-multi --output-meta=true --output-tuple --timestamp none --output-limit-lines 1 --ready-file '*' --all-kmods -- host 10.0.0.2') ;;
	*) printf 'unexpected visibility pwru argv: %s\n' "$(cat "$trace_fixture/pwru.args")" >&2; exit 1 ;;
esac
grep -F '4026533068' "$trace_fixture/work/trace.log" >/dev/null
test_context='trace-default-options-unchanged'
rm -f "$trace_fixture/work/trace.log" "$trace_fixture/pwru.args"
trace_visibility >"$trace_fixture/default-summary"
grep -Fx 'backend kprobe' "$trace_fixture/default-summary" >/dev/null
case "$(cat "$trace_fixture/pwru.args")" in
	'--backend kprobe --output-meta=false --output-tuple --timestamp none --output-limit-lines 1 --ready-file '*) ;;
	*) printf 'unexpected default pwru argv: %s\n' "$(cat "$trace_fixture/pwru.args")" >&2; exit 1 ;;
esac
case "$(cat "$trace_fixture/pwru.args")" in
	*--all-kmods*|*' -- '*) printf '%s\n' 'default trace added kmods or a filter' >&2; exit 1 ;;
esac
rm -f "$trace_fixture/work/trace.log" "$trace_fixture/pwru.args"
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
ready_file=''
while [ "$#" -gt 0 ]; do
	if [ "$1" = --ready-file ]; then
		ready_file=$2
		shift 2
		continue
	fi
	shift
done
[ -n "$ready_file" ]
: >"$ready_file"
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80'
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-native-readiness-handshake'
# The preceding negative capability matrix intentionally leaves the fixture
# in its last reduced-capability state. Reset it explicitly before this
# positive case so readiness coverage cannot depend on loop ordering.
printf 'CapEff: c001081000\n' >"$trace_fixture/status"
grep -Fx 'CapEff: c001081000' "$trace_fixture/status" >/dev/null
rm -f "$trace_fixture/work/trace.log"
NETWORK_DEBUG_PWRU_REQUIRE_READY=true NETWORK_DEBUG_WORK_DIR="$trace_fixture/work" \
	NETWORK_DEBUG_BTF_PATH="$trace_fixture/status" NETWORK_DEBUG_DEBUGFS_PATH="$trace_fixture/debug" \
	NETWORK_DEBUG_TRACEFS_PATH="$trace_fixture/trace" NETWORK_DEBUG_SECURITYFS_PATH="$trace_fixture/security" \
	NETWORK_DEBUG_MOUNTINFO_PATH="$trace_fixture/mountinfo" NETWORK_DEBUG_CAPABILITY_FILE="$trace_fixture/status" \
	PATH="$trace_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" trace --duration 1 --events 1 >/dev/null
test -f "$trace_fixture/work/trace.log"
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$$" >"$PWRU_PID_FILE"
sleep 300 &
printf '%s\n' "$!" >"$PWRU_CHILD_PID_FILE"
trap '' INT TERM
printf '%s\n' trace-event
sleep 300
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-long-child-timeout'
printf 'CapEff: c001081000\n' >"$trace_fixture/status"
rm -f "$trace_fixture/work/trace.log"
trace_timeout_error="$trace_fixture/timeout-error"
if NETWORK_DEBUG_WORK_DIR="$trace_fixture/work" \
	NETWORK_DEBUG_BTF_PATH="$trace_fixture/status" NETWORK_DEBUG_DEBUGFS_PATH="$trace_fixture/debug" \
	NETWORK_DEBUG_TRACEFS_PATH="$trace_fixture/trace" NETWORK_DEBUG_SECURITYFS_PATH="$trace_fixture/security" \
		NETWORK_DEBUG_MOUNTINFO_PATH="$trace_fixture/mountinfo" NETWORK_DEBUG_CAPABILITY_FILE="$trace_fixture/status" \
		PWRU_PID_FILE="$trace_fixture/pwru.pid" \
		PWRU_CHILD_PID_FILE="$trace_fixture/pwru-child.pid" \
		NETWORK_DEBUG_PWRU_STOP_TIMEOUT_SECONDS=1 \
	PATH="$trace_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" trace --duration 1 --events 1 > /dev/null 2>"$trace_timeout_error"; then
	printf '%s\n' 'trace unexpectedly succeeded when pwru ignored stop signals' >&2
	exit 1
fi
grep -Fx 'net-debug: pwru exited with status 137' "$trace_timeout_error" >/dev/null
test -s "$trace_fixture/pwru.pid"
test -s "$trace_fixture/pwru-child.pid"
trace_pwru_pid=$(cat "$trace_fixture/pwru.pid")
trace_child_pid=$(cat "$trace_fixture/pwru-child.pid")
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
	if ! kill -0 "$trace_pwru_pid" 2>/dev/null; then break; fi
	sleep 0.1
done
if kill -0 "$trace_pwru_pid" 2>/dev/null; then
	printf 'bounded timeout left pwru wrapper running (pid %s)\n' "$trace_pwru_pid" >&2
	exit 1
fi
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
	if ! kill -0 "$trace_child_pid" 2>/dev/null; then break; fi
	sleep 0.1
done
if kill -0 "$trace_child_pid" 2>/dev/null; then
	printf 'bounded timeout left nested pwru child running (pid %s)\n' "$trace_child_pid" >&2
	exit 1
fi
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

run_trace_fixture() {
	trace_fixture_events=$1
	NETWORK_DEBUG_WORK_DIR="$trace_fixture/work" \
		NETWORK_DEBUG_BTF_PATH="$trace_fixture/status" NETWORK_DEBUG_DEBUGFS_PATH="$trace_fixture/debug" \
		NETWORK_DEBUG_TRACEFS_PATH="$trace_fixture/trace" NETWORK_DEBUG_SECURITYFS_PATH="$trace_fixture/security" \
		NETWORK_DEBUG_MOUNTINFO_PATH="$trace_fixture/mountinfo" NETWORK_DEBUG_CAPABILITY_FILE="$trace_fixture/status" \
		NETWORK_DEBUG_PWRU_STOP_TIMEOUT_SECONDS="${trace_fixture_stop_timeout:-2}" \
		PATH="$trace_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" trace \
			--duration 1 --events "$trace_fixture_events" --output trace.log
}

run_trace_mountinfo_fixture() {
	mountinfo_debugfs=$1
	mountinfo_tracefs=$2
	mountinfo_securityfs=$3
	NETWORK_DEBUG_WORK_DIR="$trace_fixture/work" \
		NETWORK_DEBUG_BTF_PATH="$trace_fixture/status" NETWORK_DEBUG_DEBUGFS_PATH="$mountinfo_debugfs" \
		NETWORK_DEBUG_TRACEFS_PATH="$mountinfo_tracefs" NETWORK_DEBUG_SECURITYFS_PATH="$mountinfo_securityfs" \
		NETWORK_DEBUG_MOUNTINFO_PATH="$trace_fixture/mountinfo" NETWORK_DEBUG_CAPABILITY_FILE="$trace_fixture/status" \
		PATH="$trace_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" trace \
			--duration 1 --events 1 --output trace.log
}

# The mountpoint check must compare mountinfo field 5, not find a substring in
# an arbitrary field. Keep this fixture independent of the actual host mounts.
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80'
EOF
chmod +x "$trace_fixture/bin/pwru"
printf 'CapEff: c001081000\n' >"$trace_fixture/status"
test_context='trace-mountinfo-exact-field'
rm -f "$trace_fixture/work/trace.log"
run_trace_mountinfo_fixture "$trace_fixture/debug" "$trace_fixture/trace" "$trace_fixture/security" >/dev/null
test -f "$trace_fixture/work/trace.log"
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

# An extra suffix in field 5 must not satisfy the required debugfs mountpoint.
# The old substring check accepted this as a false positive.
mkdir -p "$trace_fixture/debugfs"
{
	printf '1 1 0:1 / %s rw - tmpfs tmpfs rw\n' "$trace_fixture/debugfs"
	printf '2 2 0:2 / %s rw - tmpfs tmpfs rw\n' "$trace_fixture/trace"
	printf '3 3 0:3 / %s rw - tmpfs tmpfs rw\n' "$trace_fixture/security"
} >"$trace_fixture/mountinfo"
test_context='trace-mountinfo-suffix-rejected'
rm -f "$trace_fixture/work/trace.log"
if run_trace_mountinfo_fixture "$trace_fixture/debug" "$trace_fixture/trace" "$trace_fixture/security" >/dev/null 2>&1; then
	printf '%s\n' 'trace accepted a mountpoint with an extra suffix' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

# A matching path in mountinfo field 4 or a later field is not field 5. This
# prevents prefix/suffix-looking and source/root fields from bypassing the
# exact mountpoint requirement.
{
	printf '1 1 0:1 %s /not-the-mountpoint rw - tmpfs %s rw\n' "$trace_fixture/debug" "$trace_fixture/debug"
	printf '2 2 0:2 / %s rw - tmpfs tmpfs rw\n' "$trace_fixture/trace"
	printf '3 3 0:3 / %s rw - tmpfs tmpfs rw\n' "$trace_fixture/security"
} >"$trace_fixture/mountinfo"
test_context='trace-mountinfo-misleading-fields-rejected'
rm -f "$trace_fixture/work/trace.log"
if run_trace_mountinfo_fixture "$trace_fixture/debug" "$trace_fixture/trace" "$trace_fixture/security" >/dev/null 2>&1; then
	printf '%s\n' 'trace accepted a path outside mountinfo field 5' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

# Mountinfo escapes spaces as \040. An exact escaped field must pass, while an
# escaped field with a suffix must fail. This exercises the same comparison
# for paths that are not representable as one unescaped mountinfo field.
escaped_mount_root="$trace_fixture/escaped"
escaped_debugfs="$escaped_mount_root/debug space"
escaped_tracefs="$escaped_mount_root/trace space"
escaped_securityfs="$escaped_mount_root/security space"
mkdir -p "$escaped_debugfs" "$escaped_tracefs" "$escaped_securityfs"
: >"$escaped_securityfs/lsm"
escaped_debugfs_mount=$(printf '%s' "$escaped_debugfs" | sed 's/[\\]/\\134/g; s/ /\\040/g; s/\t/\\011/g')
escaped_tracefs_mount=$(printf '%s' "$escaped_tracefs" | sed 's/[\\]/\\134/g; s/ /\\040/g; s/\t/\\011/g')
escaped_securityfs_mount=$(printf '%s' "$escaped_securityfs" | sed 's/[\\]/\\134/g; s/ /\\040/g; s/\t/\\011/g')
{
	printf '1 1 0:1 / %s rw - tmpfs tmpfs rw\n' "$escaped_debugfs_mount"
	printf '2 2 0:2 / %s rw - tmpfs tmpfs rw\n' "$escaped_tracefs_mount"
	printf '3 3 0:3 / %s rw - tmpfs tmpfs rw\n' "$escaped_securityfs_mount"
} >"$trace_fixture/mountinfo"
test_context='trace-mountinfo-escaped-exact-field'
rm -f "$trace_fixture/work/trace.log"
run_trace_mountinfo_fixture "$escaped_debugfs" "$escaped_tracefs" "$escaped_securityfs" >/dev/null
test -f "$trace_fixture/work/trace.log"
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"
{
	printf '1 1 0:1 / %s-extra rw - tmpfs tmpfs rw\n' "$escaped_debugfs_mount"
	printf '2 2 0:2 / %s rw - tmpfs tmpfs rw\n' "$escaped_tracefs_mount"
	printf '3 3 0:3 / %s rw - tmpfs tmpfs rw\n' "$escaped_securityfs_mount"
} >"$trace_fixture/mountinfo"
test_context='trace-mountinfo-escaped-suffix-rejected'
rm -f "$trace_fixture/work/trace.log"
if run_trace_mountinfo_fixture "$escaped_debugfs" "$escaped_tracefs" "$escaped_securityfs" >/dev/null 2>&1; then
	printf '%s\n' 'trace accepted an escaped mountpoint with an extra suffix' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

# Restore the ordinary exact fixture before the lifecycle cases below.
{
	printf '1 1 0:1 / %s rw - tmpfs tmpfs rw\n' "$trace_fixture/debug"
	printf '2 2 0:2 / %s rw - tmpfs tmpfs rw\n' "$trace_fixture/trace"
	printf '3 3 0:3 / %s rw - tmpfs tmpfs rw\n' "$trace_fixture/security"
} >"$trace_fixture/mountinfo"

# A real duration stop may require KILL when pwru does not exit after INT.
# Accept that path only with the wrapper-owned marker, pwru's complete
# attach/signal/detach lifecycle, and non-empty bounded tuple evidence.
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80'
printf '%s\n' '2026/08/27 20:00:00 INFO Attaching kprobes via=kprobe' >&2
printf '%s\n' '2026/08/27 20:00:01 INFO Received signal, exiting program..' >&2
printf '%s\n' '2026/08/27 20:00:01 INFO Detaching kprobes...' >&2
trap '' INT TERM
while :; do sleep 300; done
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-controlled-timeout-with-evidence'
rm -f "$trace_fixture/work/trace.log"
run_trace_fixture 3 >"$trace_fixture/controlled-timeout-summary"
grep -Fx 'event_count 1' "$trace_fixture/controlled-timeout-summary" >/dev/null
grep -F -- '->' "$trace_fixture/work/trace.log" >/dev/null
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

# Lifecycle-looking diagnostics cannot forge success when the trace has no
# packet tuple evidence.
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '2026/08/27 20:00:00 INFO Attaching kprobes via=kprobe' >&2
printf '%s\n' '2026/08/27 20:00:01 INFO Received signal, exiting program..' >&2
printf '%s\n' '2026/08/27 20:00:01 INFO Detaching kprobes...' >&2
trap '' INT TERM
while :; do sleep 300; done
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-controlled-timeout-empty-evidence'
rm -f "$trace_fixture/work/trace.log"
if run_trace_fixture 3 >"$trace_fixture/controlled-timeout-empty-summary" 2>"$trace_fixture/controlled-timeout-empty-error"; then
	printf '%s\n' 'trace accepted a controlled timeout without packet evidence' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

# pwru v1.0.12 reports reaching --output-limit-lines as an informational
# completion marker on stderr but exits with status 1. Accept only that exact
# marker/count pair and only when stdout contains the same number of events.
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' 'SKB CPU PROCESS TUPLE FUNC' 'header-only metadata'
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80' '10.0.0.1:12346 -> 10.0.0.2:80' '10.0.0.1:12347 -> 10.0.0.2:80'
printf '%s\n' '2026/08/27 20:00:00 INFO Printed events, exiting program.. count=3' >&2
exit 1
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-limit-status-1'
rm -f "$trace_fixture/work/trace.log"
run_trace_fixture 3 >"$trace_fixture/limit-summary"
grep -Fx 'event_count 3' "$trace_fixture/limit-summary" >/dev/null
test "$(wc -l <"$trace_fixture/work/trace.log" | tr -d ' ')" -eq 3
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

# Reaching the event limit makes pwru detach its kprobes, which can outlast
# the trace duration on real kernels. The stop grace covers that detach, so a
# natural exit after the duration deadline is still a bounded completion.
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80' '10.0.0.1:12346 -> 10.0.0.2:80' '10.0.0.1:12347 -> 10.0.0.2:80'
printf '%s\n' '2026/08/27 20:00:00 INFO Attaching kprobes via=kprobe' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Printed events, exiting program.. count=3' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Detaching kprobes...' >&2
trap '' INT TERM
sleep 2
exit 1
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-limit-slow-detach-within-grace'
rm -f "$trace_fixture/work/trace.log"
trace_fixture_stop_timeout=5 run_trace_fixture 3 >"$trace_fixture/slow-detach-summary"
grep -Fx 'event_count 3' "$trace_fixture/slow-detach-summary" >/dev/null
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

# When detach outlasts even the grace, the forced stop is accepted only with
# pwru's exact event-limit marker, the attach/detach lifecycle, and exactly
# that many tuples.
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80' '10.0.0.1:12346 -> 10.0.0.2:80' '10.0.0.1:12347 -> 10.0.0.2:80'
printf '%s\n' '2026/08/27 20:00:00 INFO Attaching kprobes via=kprobe' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Printed events, exiting program.. count=3' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Detaching kprobes...' >&2
trap '' INT TERM
while :; do sleep 300; done
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-limit-stopped-during-detach'
rm -f "$trace_fixture/work/trace.log"
run_trace_fixture 3 >"$trace_fixture/limit-stopped-summary"
grep -Fx 'event_count 3' "$trace_fixture/limit-stopped-summary" >/dev/null
test "$(wc -l <"$trace_fixture/work/trace.log" | tr -d ' ')" -eq 3
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80' '10.0.0.1:12346 -> 10.0.0.2:80'
printf '%s\n' '2026/08/27 20:00:00 INFO Attaching kprobes via=kprobe' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Printed events, exiting program.. count=3' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Detaching kprobes...' >&2
trap '' INT TERM
while :; do sleep 300; done
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-limit-stopped-evidence-mismatch'
rm -f "$trace_fixture/work/trace.log"
if run_trace_fixture 3 >"$trace_fixture/limit-stopped-mismatch-summary" 2>"$trace_fixture/limit-stopped-mismatch-error"; then
	printf '%s\n' 'trace accepted a forced detach stop whose evidence did not match the limit marker' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"

cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80' '10.0.0.1:12346 -> 10.0.0.2:80'
printf '%s\n' '2026/08/27 20:00:00 INFO Attaching kprobes via=kprobe' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Printed events, exiting program.. count=2' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Detaching kprobes...' >&2
trap '' INT TERM
while :; do sleep 300; done
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-limit-stopped-false-marker'
rm -f "$trace_fixture/work/trace.log"
if run_trace_fixture 3 >"$trace_fixture/limit-stopped-false-summary" 2>"$trace_fixture/limit-stopped-false-error"; then
	printf '%s\n' 'trace accepted a forced detach stop with a marker for a different event limit' >&2
	exit 1
fi
grep -Fx 'net-debug: pwru exited with status 137' "$trace_fixture/limit-stopped-false-error" >/dev/null
test ! -e "$trace_fixture/work/trace.log"

# The watchdog may interrupt pwru while it detaches after its event limit,
# leaving both markers (emitted directly: a shell fixture cannot trap the INT
# that its background launch ignores). The exact limit count must still be enforced, and a
# limit marker for a different count fails closed.
cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80' '10.0.0.1:12346 -> 10.0.0.2:80'
printf '%s\n' '2026/08/27 20:00:00 INFO Attaching kprobes via=kprobe' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Printed events, exiting program.. count=3' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Detaching kprobes...' >&2
printf '%s\n' '2026/08/27 20:00:01 INFO Received signal, exiting program..' >&2
trap '' INT TERM
while :; do sleep 300; done
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-limit-and-signal-evidence-mismatch'
rm -f "$trace_fixture/work/trace.log"
if run_trace_fixture 3 >"$trace_fixture/limit-signal-mismatch-summary" 2>"$trace_fixture/limit-signal-mismatch-error"; then
	printf '%s\n' 'trace accepted a limit-and-signal stop whose evidence did not match the limit marker' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"

cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80' '10.0.0.1:12346 -> 10.0.0.2:80'
printf '%s\n' '2026/08/27 20:00:00 INFO Attaching kprobes via=kprobe' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Printed events, exiting program.. count=2' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Detaching kprobes...' >&2
printf '%s\n' '2026/08/27 20:00:01 INFO Received signal, exiting program..' >&2
trap '' INT TERM
while :; do sleep 300; done
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-signal-with-false-limit-marker'
rm -f "$trace_fixture/work/trace.log"
if run_trace_fixture 3 >"$trace_fixture/signal-false-limit-summary" 2>"$trace_fixture/signal-false-limit-error"; then
	printf '%s\n' 'trace accepted a signal stop carrying a limit marker for a different event limit' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"

cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80' '10.0.0.1:12346 -> 10.0.0.2:80' '10.0.0.1:12347 -> 10.0.0.2:80'
printf '%s\n' '2026/08/27 20:00:00 INFO Attaching kprobes via=kprobe' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Printed events, exiting program.. count=3' >&2
printf '%s\n' '2026/08/27 20:00:00 INFO Detaching kprobes...' >&2
printf '%s\n' '2026/08/27 20:00:01 INFO Received signal, exiting program..' >&2
trap '' INT TERM
while :; do sleep 300; done
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-limit-and-signal-exact'
rm -f "$trace_fixture/work/trace.log"
run_trace_fixture 3 >"$trace_fixture/limit-signal-summary"
grep -Fx 'event_count 3' "$trace_fixture/limit-signal-summary" >/dev/null
test "$(wc -l <"$trace_fixture/work/trace.log" | tr -d ' ')" -eq 3
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"
rm -f "$trace_fixture/work/trace.log"

test_context='trace-stop-timeout-bound'
if trace_fixture_stop_timeout=121 run_trace_fixture 3 >/dev/null 2>&1; then
	printf '%s\n' 'trace accepted a stop grace above 120 seconds' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"

cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' 'SKB CPU PROCESS TUPLE FUNC' 'header-only metadata'
exit 0
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-empty-evidence'
rm -f "$trace_fixture/work/trace.log"
if run_trace_fixture 3 >"$trace_fixture/empty-summary" 2>"$trace_fixture/empty-error"; then
	printf '%s\n' 'trace accepted header-only output as packet evidence' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80' '10.0.0.1:12346 -> 10.0.0.2:80' '10.0.0.1:12347 -> 10.0.0.2:80'
printf '%s\n' '2026/08/27 20:00:00 INFO Printed events, exiting program.. count=2' >&2
exit 1
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-limit-false-marker'
rm -f "$trace_fixture/work/trace.log"
if run_trace_fixture 3 >"$trace_fixture/false-marker-summary" 2>"$trace_fixture/false-marker-error"; then
	printf '%s\n' 'trace accepted a false bounded-completion marker' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' '10.0.0.1:12345 -> 10.0.0.2:80' '10.0.0.1:12346 -> 10.0.0.2:80'
printf '%s\n' '2026/08/27 20:00:00 INFO Printed events, exiting program.. count=3' >&2
exit 1
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-limit-evidence-mismatch'
rm -f "$trace_fixture/work/trace.log"
if run_trace_fixture 3 >"$trace_fixture/mismatch-summary" 2>"$trace_fixture/mismatch-error"; then
	printf '%s\n' 'trace accepted evidence with a mismatched bounded-completion count' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"

cat >"$trace_fixture/bin/pwru" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' 'pwru: failed to attach kprobe' >&2
exit 1
EOF
chmod +x "$trace_fixture/bin/pwru"
test_context='trace-status-1-runtime-error'
rm -f "$trace_fixture/work/trace.log"
if run_trace_fixture 3 >"$trace_fixture/error-summary" 2>"$trace_fixture/error-error"; then
	printf '%s\n' 'trace accepted an unmarked pwru runtime error' >&2
	exit 1
fi
test ! -e "$trace_fixture/work/trace.log"
test -z "$(find "$trace_fixture/work" -maxdepth 1 -name '.net-debug.*' -print -quit)"
else
	printf '%s\n' 'skipping Linux-only trace success fixture on non-Linux host' >&2
fi
rm -rf "$trace_fixture"
echo 'network-debug image checks passed'
