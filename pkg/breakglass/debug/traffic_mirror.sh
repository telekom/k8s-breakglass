#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
#
# Controller-owned session traffic mirror helper. The controller renders the
# whole Pod; requesters never supply commands, arguments or environment.
#
#   attach    mirror INTERFACE of the target network namespace into a veth
#             pair whose peer lives in this Pod, then wait. SIGTERM detaches.
#   capture   wait for the mirror device and run the bounded tcpdump.
#   teardown  remove this operation's tc filters and mirror device from the
#             target network namespace and verify that none remain.
#
# The tc filters carry the operation cookie, so teardown never removes a
# filter of another session or tool. The target network namespace is found
# from the Pod UID in /proc/*/cgroup (hostPID) or is PID 1's for a Node.
set -eu

mode=${1:-}
peer=bgmirror0

log() {
	printf '{"event":"%s","operation":"%s","detail":"%s"}\n' "$1" "${MIRROR_OPERATION:-}" "${2:-}"
}

fail() {
	log "$1" "$2" >&2
	printf '%s: %s\n' "$1" "$2" >/dev/termination-log 2>/dev/null || true
	exit 1
}

require_env() {
	: "${MIRROR_OPERATION:?}" "${MIRROR_INTERFACE:?}" "${MIRROR_VETH:?}" "${MIRROR_COOKIE:?}" "${MIRROR_PREF:?}" "${MIRROR_SELF_UID:?}"
}

# pod_pid prints a PID whose cgroup belongs to the Pod UID, or fails.
pod_pid() {
	uid=$1
	alt=$(printf '%s' "$uid" | tr - _)
	for cgroup in /proc/[0-9]*/cgroup; do
		if grep -q -e "pod$uid" -e "pod$alt" "$cgroup" 2>/dev/null; then
			pid=${cgroup#/proc/}
			printf '%s\n' "${pid%/cgroup}"
			return 0
		fi
	done
	return 1
}

# check_scan refuses to run when the scan cannot even find this Pod, so an
# unreadable /proc is never mistaken for a target that is gone.
check_scan() {
	pod_pid "$MIRROR_SELF_UID" >/dev/null || fail scan-failed "cannot resolve Pods from /proc; hostPID and SYS_PTRACE are required"
}

# target_pid prints the target network namespace owner: PID 1 for a Node.
target_pid() {
	if [ -z "${MIRROR_POD_UID:-}" ]; then
		printf '1\n'
		return 0
	fi
	pod_pid "$MIRROR_POD_UID"
}

in_target() {
	nsenter -t "$tpid" -n -- "$@"
}

hooks() {
	case "${MIRROR_DIRECTION:-both}" in
	ingress) printf 'ingress\n' ;;
	egress) printf 'egress\n' ;;
	*) printf 'ingress\negress\n' ;;
	esac
}

# owned_filters prints the hooks that still carry this operation's cookie.
owned_filters() {
	for hook in ingress egress; do
		if in_target tc filter show dev "$MIRROR_INTERFACE" "$hook" 2>/dev/null | grep -q "cookie $MIRROR_COOKIE"; then
			printf '%s\n' "$hook"
		fi
	done
}

detach() {
	for hook in $(owned_filters); do
		in_target tc filter del dev "$MIRROR_INTERFACE" "$hook" pref "$MIRROR_PREF" 2>/dev/null || true
	done
	in_target ip link del "$MIRROR_VETH" 2>/dev/null || true
	# ponytail: an empty clsact is deleted even if another tool created it;
	# a tool that attaches later recreates it.
	if in_target tc qdisc show dev "$MIRROR_INTERFACE" 2>/dev/null | grep -q 'qdisc clsact' &&
		[ -z "$(in_target tc filter show dev "$MIRROR_INTERFACE" ingress 2>/dev/null)" ] &&
		[ -z "$(in_target tc filter show dev "$MIRROR_INTERFACE" egress 2>/dev/null)" ]; then
		in_target tc qdisc del dev "$MIRROR_INTERFACE" clsact 2>/dev/null || true
	fi
}

verify_detached() {
	[ -z "$(owned_filters)" ] || fail teardown-failed "tc filters with the operation cookie remain"
	! in_target ip link show dev "$MIRROR_VETH" >/dev/null 2>&1 || fail teardown-failed "mirror device remains"
}

attach() {
	require_env
	check_scan
	tpid=$(target_pid) || fail target-missing "the target Pod has no process on this Node"
	if [ -n "${MIRROR_POD_UID:-}" ]; then
		[ "$(readlink "/proc/$tpid/ns/net")" != "$(readlink /proc/1/ns/net)" ] || fail target-mismatch "the target Pod uses the host network"
		in_target ip -o addr show | grep -F -q " ${MIRROR_POD_IP:?}/" || fail target-mismatch "the target network namespace does not own the Pod IP"
	fi
	in_target ip link show dev "$MIRROR_INTERFACE" >/dev/null 2>&1 || fail interface-missing "interface $MIRROR_INTERFACE does not exist"
	detach
	for hook in ingress egress; do
		if [ -n "$(in_target tc filter show dev "$MIRROR_INTERFACE" "$hook" pref "$MIRROR_PREF" 2>/dev/null)" ]; then
			fail pref-busy "another filter uses preference $MIRROR_PREF on $hook"
		fi
	done
	# A failed attach leaves no partial state; SIGTERM (session end or the
	# Pod's activeDeadlineSeconds) detaches and verifies before exiting.
	trap 'detach' EXIT
	trap 'detach; verify_detached; log mirror-stopped; exit 0' TERM INT
	in_target ip link add name "$MIRROR_VETH" type veth peer name "$peer" netns "$$"
	in_target ip link set "$MIRROR_VETH" up
	ip link set "$peer" up
	# Only the mirrored copies pass this bucket; excess copies are dropped.
	in_target tc qdisc replace dev "$MIRROR_VETH" root tbf rate "${MIRROR_RATE_MBIT:?}mbit" burst 64kb latency 100ms
	in_target tc qdisc show dev "$MIRROR_INTERFACE" | grep -q 'qdisc clsact' || in_target tc qdisc add dev "$MIRROR_INTERFACE" clsact
	for hook in $(hooks); do
		# u32 "match u32 0 0" matches every packet; unlike matchall it is
		# available on every kernel with tc.
		in_target tc filter add dev "$MIRROR_INTERFACE" "$hook" pref "$MIRROR_PREF" protocol all u32 match u32 0 0 \
			action mirred egress mirror dev "$MIRROR_VETH" cookie "$MIRROR_COOKIE"
	done
	: >/run/mirror/attached
	log mirror-started "$MIRROR_INTERFACE"
	while :; do
		sleep 3600 &
		wait $! || true
	done
}

capture() {
	attempts=0
	until ip link show dev "$peer" >/dev/null 2>&1; do
		attempts=$((attempts + 1))
		[ "$attempts" -le 120 ] || fail capture-failed "mirror device did not appear"
		sleep 1
	done
	exec tcpdump -p -n -l -e -i "$peer" -s "${MIRROR_SNAPLEN:?}" -c "${MIRROR_MAX_PACKETS:?}" -- ${MIRROR_FILTER:+"$MIRROR_FILTER"}
}

teardown() {
	require_env
	check_scan
	if ! tpid=$(target_pid); then
		log teardown-verified "target network namespace is gone"
		return 0
	fi
	detach
	verify_detached
	log teardown-verified "$MIRROR_INTERFACE"
}

case "$mode" in
attach) attach ;;
capture) capture ;;
teardown) teardown ;;
*)
	printf 'usage: traffic-mirror attach|capture|teardown\n' >&2
	exit 2
	;;
esac
