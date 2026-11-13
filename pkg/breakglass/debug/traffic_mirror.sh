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
	: "${MIRROR_OPERATION:?}" "${MIRROR_INTERFACE:?}" "${MIRROR_VETH:?}" "${MIRROR_COOKIE:?}" "${MIRROR_PREF:?}"
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

# check_scan refuses to run when the scan cannot see other Pods or enter
# PID 1, so an unreadable /proc is never mistaken for a target that is gone.
# Our own cgroup reads as "/" in a private cgroup namespace, so we look for
# any kubepods cgroup instead of our own Pod UID.
check_scan() {
	readlink /proc/1/ns/net >/dev/null 2>&1 || fail scan-failed "cannot enter PID 1; hostPID and SYS_PTRACE are required"
	grep -q -s kubepods /proc/[0-9]*/cgroup || fail scan-failed "cannot see Pod cgroups in /proc; hostPID is required"
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

# link_absent succeeds only when the namespace was inspected and the link is
# gone; any other inspection failure stops the script.
link_absent() {
	if out=$(in_target ip link show dev "$1" 2>&1); then
		return 1
	fi
	case "$out" in
	*"does not exist"*) return 0 ;;
	esac
	fail inspect-failed "cannot inspect $1: $out"
}

# show_filters prints the filters of one hook; a missing interface has none.
show_filters() {
	if out=$(in_target tc filter show dev "$MIRROR_INTERFACE" "$1" 2>&1); then
		printf '%s\n' "$out"
		return 0
	fi
	link_absent "$MIRROR_INTERFACE" || fail inspect-failed "cannot list $1 filters: $out"
}

# owned_handles prints the filter handles at this operation's preference whose
# action carries the operation cookie. Other filters are never selected.
owned_handles() {
	filters=$(show_filters "$1") || exit 1
	printf '%s\n' "$filters" | awk -v cookie="cookie $MIRROR_COOKIE" -v pref="pref $MIRROR_PREF " '
		/^filter / {
			handle = ""
			if (index($0, pref) && match($0, /handle 0x[0-9a-f]+/)) handle = substr($0, RSTART + 7, RLENGTH - 7)
		}
		index($0, cookie) && handle != "" { print handle }'
}

# keys_at_pref counts the filters left at this operation's preference.
keys_at_pref() {
	filters=$(show_filters "$1") || exit 1
	printf '%s\n' "$filters" | grep "pref $MIRROR_PREF " | grep -c 'handle 0x' || true
}

detach() {
	for hook in ingress egress; do
		handles=$(owned_handles "$hook") || exit 1
		for handle in $handles; do
			in_target tc filter del dev "$MIRROR_INTERFACE" "$hook" pref "$MIRROR_PREF" handle "$handle" protocol all basic ||
				fail teardown-failed "cannot delete filter $handle on $hook"
		done
		# Drop an empty classifier left at our preference, never foreign filters.
		if [ -n "$handles" ] && [ "$(keys_at_pref "$hook")" = 0 ]; then
			in_target tc filter del dev "$MIRROR_INTERFACE" "$hook" pref "$MIRROR_PREF" protocol all basic 2>/dev/null || true
		fi
	done
	if ! link_absent "$MIRROR_VETH"; then
		in_target ip link del "$MIRROR_VETH" || fail teardown-failed "cannot delete $MIRROR_VETH"
	fi
	# ponytail: an empty clsact is deleted even if another tool created it;
	# a tool that attaches later recreates it.
	ingress=$(show_filters ingress) || exit 1
	egress=$(show_filters egress) || exit 1
	if [ -z "$ingress$egress" ] && in_target tc qdisc show dev "$MIRROR_INTERFACE" 2>/dev/null | grep -q 'qdisc clsact'; then
		in_target tc qdisc del dev "$MIRROR_INTERFACE" clsact 2>/dev/null || true
	fi
}

verify_detached() {
	for hook in ingress egress; do
		handles=$(owned_handles "$hook") || exit 1
		[ -z "$handles" ] || fail teardown-failed "tc filters with the operation cookie remain on $hook"
	done
	link_absent "$MIRROR_VETH" || fail teardown-failed "mirror device remains"
}

# remaining prints the seconds until the approved session expiry.
remaining() {
	printf '%s\n' $((${MIRROR_EXPIRES_UNIX:?} - $(date +%s)))
}

attach() {
	require_env
	check_scan
	[ "$(remaining)" -gt 0 ] || fail expired "the approved session has expired"
	tpid=$(target_pid) || fail target-missing "the target Pod has no process on this Node"
	in_target true || fail inspect-failed "cannot enter the target network namespace"
	if [ -n "${MIRROR_POD_UID:-}" ]; then
		[ "$(readlink "/proc/$tpid/ns/net")" != "$(readlink /proc/1/ns/net)" ] || fail target-mismatch "the target Pod uses the host network"
		in_target ip -o addr show | grep -F -q " ${MIRROR_POD_IP:?}/" || fail target-mismatch "the target network namespace does not own the Pod IP"
	fi
	! link_absent "$MIRROR_INTERFACE" || fail interface-missing "interface $MIRROR_INTERFACE does not exist"
	detach
	for hook in ingress egress; do
		if [ -n "$(in_target tc filter show dev "$MIRROR_INTERFACE" "$hook" pref "$MIRROR_PREF")" ]; then
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
		# basic without an ematch matches every packet. Unlike matchall it is
		# built on every kernel with tc, and unlike u32 its filters are per hook.
		in_target tc filter add dev "$MIRROR_INTERFACE" "$hook" pref "$MIRROR_PREF" protocol all basic \
			action mirred egress mirror dev "$MIRROR_VETH" cookie "$MIRROR_COOKIE"
	done
	: >/run/mirror/attached
	log mirror-started "$MIRROR_INTERFACE"
	# The absolute approved expiry ends the mirror even without the controller.
	while left=$(remaining) && [ "$left" -gt 0 ]; do
		[ "$left" -le 30 ] || left=30
		sleep "$left" &
		wait $! || true
	done
	detach
	verify_detached
	trap - EXIT
	log mirror-expired "$MIRROR_INTERFACE"
}

capture() {
	attempts=0
	until ip link show dev "$peer" >/dev/null 2>&1; do
		attempts=$((attempts + 1))
		[ "$attempts" -le 120 ] || fail capture-failed "mirror device did not appear"
		sleep 1
	done
	left=$(remaining)
	[ "$left" -gt 0 ] || exit 0
	# timeout exits 124 at the approved expiry.
	exec timeout "$left" tcpdump -p -n -l -e -i "$peer" -s "${MIRROR_SNAPLEN:?}" -c "${MIRROR_MAX_PACKETS:?}" -- ${MIRROR_FILTER:+"$MIRROR_FILTER"}
}

teardown() {
	require_env
	check_scan
	if ! tpid=$(target_pid); then
		log teardown-verified "target network namespace is gone"
		return 0
	fi
	in_target true || fail inspect-failed "cannot enter the target network namespace"
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
