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
		PATH="$trace_fixture/bin:/usr/bin:/bin" sh "$root/scripts/net-debug" trace \
			--duration 1 --events "$trace_fixture_events" --output trace.log
}

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
