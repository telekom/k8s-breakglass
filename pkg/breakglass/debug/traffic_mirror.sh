#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
#
# Controller-owned session traffic mirror helper. The controller renders the
# whole Pod; requesters never supply commands, arguments or environment.
#
#   attach    (agent Pod, hostPID) mirror INTERFACE of the target network
#             namespace into a veth pair whose peer is moved into the
#             separate capture Pod, then wait. SIGTERM detaches.
#   capture   (capture Pod, no hostPID) wait until the agent brought the
#             mirror device up, then run the bounded tcpdump.
#   teardown  remove this operation's tc filters and mirror device from the
#             target network namespace and verify that none remain.
#
# The tc filters carry the operation cookie, so teardown never removes a
# filter of another session or tool. The target network namespace is found
# from the Pod UID in /proc/*/cgroup (hostPID) or is PID 1's for a Node.
set -eu

mode=${1:-}
peer=bgmirror0
# The agent writes its readiness marker here after a complete attach.
run_dir=${MIRROR_RUN_DIR:-/run/mirror}
# The host process tree (hostPID); tests substitute a fake one.
proc=${MIRROR_PROC_ROOT:-/proc}

# ns_id prints the identity (device and inode) of a namespace reference.
ns_id() {
	stat -L -c '%d:%i' "$1"
}

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

# pod_pid UID IP prints the PID of a process of the Pod whose network
# namespace owns IP, "recreated" when the Pod has processes and every one of
# their namespaces was inspected but none owns IP, or nothing when the Pod has
# no process on this Node. A failed inspection stops the script.
pod_pid() {
	uid=$1
	ip=$2
	alt=$(printf '%s' "$uid" | tr - _)
	found=""
	for cgroup in "$proc"/[0-9]*/cgroup; do
		grep -q -e "pod$uid" -e "pod$alt" "$cgroup" 2>/dev/null || continue
		pid=${cgroup#"$proc"/}
		pid=${pid%/cgroup}
		if ! addrs=$(nsenter --net="$proc/$pid/ns/net" -- ip -o addr show 2>&1); then
			# The process may have exited since the scan; otherwise fail closed.
			[ ! -e "$proc/$pid" ] && continue
			fail inspect-failed "cannot inspect the network namespace of PID $pid: $addrs"
		fi
		found=1
		if printf '%s\n' "$addrs" | grep -F -q " $ip/"; then
			printf '%s\n' "$pid"
			return 0
		fi
	done
	[ -z "$found" ] || printf 'recreated\n'
}

# check_scan refuses to run when the scan cannot see other Pods or enter
# PID 1, so an unreadable /proc is never mistaken for a target that is gone.
# Our own cgroup reads as "/" in a private cgroup namespace, so we look for
# any kubepods cgroup instead of our own Pod UID.
check_scan() {
	ns_id "$proc/1/ns/net" >/dev/null 2>&1 || fail scan-failed "cannot enter PID 1; hostPID and SYS_PTRACE are required"
	grep -q -s kubepods "$proc"/[0-9]*/cgroup || fail scan-failed "cannot see Pod cgroups in /proc; hostPID is required"
}

# target_pid prints the target network namespace owner: PID 1 for a Node.
# It prints nothing when the target Pod is gone from this Node.
target_pid() {
	if [ -z "${MIRROR_POD_UID:-}" ]; then
		printf '1\n'
		return 0
	fi
	pod_pid "$MIRROR_POD_UID" "${MIRROR_POD_IP:?}"
}

# pin_target opens the target network namespace once. Every later step
# enters it through descriptor 3, so a reused PID can never redirect the
# helper into another namespace after the identity checks.
pin_target() {
	exec 3<"$proc/$tpid/ns/net" || fail inspect-failed "cannot open the target network namespace"
	confirm_pinned 3 "$tpid" "${MIRROR_POD_UID:-}"
}

# confirm_pinned FD PID [UID] rejects a PID that was reused between the scan
# and the open: the descriptor must still be that PID's namespace, and the
# PID must still belong to the Pod.
confirm_pinned() {
	[ "$(ns_id "/proc/self/fd/$1")" = "$(ns_id "$proc/$2/ns/net" 2>/dev/null)" ] ||
		fail target-mismatch "PID $2 changed its network namespace while it was pinned"
	if [ -n "${3:-}" ]; then
		alt=$(printf '%s' "$3" | tr - _)
		grep -q -e "pod$3" -e "pod$alt" "$proc/$2/cgroup" 2>/dev/null || fail target-mismatch "PID $2 no longer belongs to Pod $3"
	fi
}

in_target() {
	nsenter --net=/proc/self/fd/3 -- "$@"
}

# The capture Pod's network namespace is pinned on descriptor 4.
in_capture() {
	nsenter --net=/proc/self/fd/4 -- "$@"
}

# verify_pinned_target repeats the identity checks through the pinned
# descriptor: a Pod target is not the host namespace and owns the Pod IP.
verify_pinned_target() {
	in_target true || fail inspect-failed "cannot enter the target network namespace"
	if [ -n "${MIRROR_POD_UID:-}" ]; then
		[ "$(ns_id /proc/self/fd/3)" != "$(ns_id "$proc/1/ns/net")" ] || fail target-mismatch "the target Pod uses the host network"
		in_target ip -o addr show | grep -F -q " ${MIRROR_POD_IP:?}/" || fail target-mismatch "the target network namespace does not own the Pod IP"
	fi
}

# Nodes booted with ipv6.disable=1 reject addrgenmode.
addrgen() {
	if [ -d "$proc/sys/net/ipv6" ]; then
		printf 'addrgenmode none\n'
	fi
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

# links prints the name of every link in the target network namespace.
links() {
	out=$(in_target ip -o link show 2>&1) || fail inspect-failed "cannot list links: $out"
	printf '%s\n' "$out" | awk -F': ' '{ sub(/@.*/, "", $2); print $2 }'
}

# link_id prints the ifindex and hardware address of the mirrored interface,
# or nothing when it is gone.
link_id() {
	in_target ip -o link show dev "$MIRROR_INTERFACE" 2>/dev/null |
		awk '{ id = $1; for (i = 2; i < NF; i++) if ($i ~ /^link\//) id = id " " $(i + 1); print id }'
}

# show_filters DEV HOOK prints the filters of one hook; a missing device has none.
show_filters() {
	if out=$(in_target tc filter show dev "$1" "$2" 2>&1); then
		printf '%s\n' "$out"
		return 0
	fi
	link_absent "$1" || fail inspect-failed "cannot list $2 filters of $1: $out"
}

# owned_handles DEV HOOK prints the filter handles at this operation's
# preference whose action carries the operation cookie. Other filters are
# never selected.
owned_handles() {
	filters=$(show_filters "$1" "$2") || exit 1
	printf '%s\n' "$filters" | awk -v cookie="cookie $MIRROR_COOKIE" -v pref="pref $MIRROR_PREF " '
		/^filter / {
			handle = ""
			if (index($0, pref) && match($0, /handle 0x[0-9a-f]+/)) handle = substr($0, RSTART + 7, RLENGTH - 7)
		}
		index($0, cookie) && handle != "" { print handle }'
}

# keys_at_pref DEV HOOK counts the filters left at this operation's preference.
keys_at_pref() {
	filters=$(show_filters "$1" "$2") || exit 1
	printf '%s\n' "$filters" | grep "pref $MIRROR_PREF " | grep -c 'handle 0x' || true
}

# detach scans every link, not only MIRROR_INTERFACE, so the filters of a
# renamed interface are removed as well. "detach keep-device" leaves the
# mirror device to the teardown.
detach() {
	devs=$(links) || exit 1
	for dev in $devs; do
		for hook in ingress egress; do
			handles=$(owned_handles "$dev" "$hook") || exit 1
			for handle in $handles; do
				in_target tc filter del dev "$dev" "$hook" pref "$MIRROR_PREF" handle "$handle" protocol all basic ||
					fail teardown-failed "cannot delete filter $handle on $dev $hook"
			done
			# Drop an empty classifier left at our preference, never foreign filters.
			if [ -n "$handles" ] && [ "$(keys_at_pref "$dev" "$hook")" = 0 ]; then
				in_target tc filter del dev "$dev" "$hook" pref "$MIRROR_PREF" protocol all basic 2>/dev/null || true
			fi
		done
	done
	if [ "${1:-}" != keep-device ] && ! link_absent "$MIRROR_VETH"; then
		in_target ip link del "$MIRROR_VETH" || fail teardown-failed "cannot delete $MIRROR_VETH"
	fi
	# The clsact qdisc is left in place: another tool may own it or be about
	# to attach to it, and an empty clsact does not touch any packet.
}

verify_detached() {
	devs=$(links) || exit 1
	for dev in $devs; do
		for hook in ingress egress; do
			handles=$(owned_handles "$dev" "$hook") || exit 1
			[ -z "$handles" ] || fail teardown-unverifiable "tc filters with the operation cookie remain on $dev $hook"
		done
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
	tpid=$(target_pid) || exit 1
	case "$tpid" in
	"") fail target-missing "the target Pod has no process on this Node" ;;
	recreated) fail target-mismatch "no network namespace of the target Pod owns the approved Pod IP" ;;
	esac
	pin_target
	verify_pinned_target
	cpid=$(pod_pid "${MIRROR_CAPTURE_POD_UID:?}" "${MIRROR_CAPTURE_POD_IP:?}") || exit 1
	case "$cpid" in
	"" | recreated) fail capture-missing "the capture Pod is not running with its approved IP on this Node" ;;
	esac
	exec 4<"$proc/$cpid/ns/net" || fail inspect-failed "cannot open the capture network namespace"
	confirm_pinned 4 "$cpid" "$MIRROR_CAPTURE_POD_UID"
	[ "$(ns_id /proc/self/fd/4)" != "$(ns_id "$proc/1/ns/net")" ] || fail capture-missing "the capture Pod uses the host network"
	[ "$(ns_id /proc/self/fd/4)" != "$(ns_id /proc/self/fd/3)" ] || fail capture-missing "the capture Pod shares the target network namespace"
	in_capture ip -o addr show | grep -F -q " $MIRROR_CAPTURE_POD_IP/" || fail capture-missing "the capture network namespace does not own the capture Pod IP"
	! link_absent "$MIRROR_INTERFACE" || fail interface-missing "interface $MIRROR_INTERFACE does not exist"
	ifid=$(link_id)
	[ -n "$ifid" ] || fail inspect-failed "cannot read the index and address of $MIRROR_INTERFACE"
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
	# The peer goes straight into the pinned capture namespace.
	in_target ip link add name "$MIRROR_VETH" type veth peer name "$peer" netns /proc/self/fd/4
	# The pair carries mirrored copies only, never a path into the source:
	# no IPv6 link-local addresses, no ARP, and every frame arriving from the
	# capture side is dropped before the source network stack.
	# shellcheck disable=SC2046 # addrgen prints nothing or two words.
	in_target ip link set dev "$MIRROR_VETH" $(addrgen) arp off
	# shellcheck disable=SC2046
	in_capture ip link set dev "$peer" $(addrgen) arp off
	in_target tc qdisc add dev "$MIRROR_VETH" clsact
	in_target tc filter add dev "$MIRROR_VETH" ingress pref 1 protocol all basic action drop
	in_target ip link set "$MIRROR_VETH" up
	# Only the mirrored copies pass this bucket; excess copies are dropped.
	in_target tc qdisc replace dev "$MIRROR_VETH" root tbf rate "${MIRROR_RATE_MBIT:?}mbit" burst 64kb latency 100ms
	in_target tc qdisc show dev "$MIRROR_INTERFACE" | grep -q 'qdisc clsact' || in_target tc qdisc add dev "$MIRROR_INTERFACE" clsact
	for hook in $(hooks); do
		# basic without an ematch matches every packet. Unlike matchall it is
		# built on every kernel with tc, and unlike u32 its filters are per hook.
		# continue lets classification reach the filters at higher preferences;
		# mirred's default pipe would end it here and bypass them.
		in_target tc filter add dev "$MIRROR_INTERFACE" "$hook" pref "$MIRROR_PREF" protocol all basic \
			action mirred egress mirror dev "$MIRROR_VETH" continue cookie "$MIRROR_COOKIE"
	done
	# Bringing the capture side up last tells the capture Pod that the
	# attach is complete.
	in_capture ip link set "$peer" up
	: >"$run_dir/attached"
	log mirror-started "$MIRROR_INTERFACE"
	# The absolute approved expiry ends the mirror even without the controller.
	# The identity is checked right after the attach, after every wait and at
	# the expiry: the filters follow a renamed interface and vanish with a
	# re-created one.
	while :; do
		if [ "$(link_id)" != "$ifid" ]; then
			# Deleting the device would fail the capture first and hide this
			# cause; the teardown removes it.
			trap - EXIT
			detach keep-device
			fail interface-changed "interface $MIRROR_INTERFACE was renamed or re-created; the mirror is lost"
		fi
		left=$(remaining)
		[ "$left" -gt 0 ] || break
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
	# The agent brings the device up only after a complete attach; an
	# existing but down device would make tcpdump fail. The agent Pod is
	# created after this Pod runs, so allow for its image pull.
	attempts=0
	until ip -o link show dev "$peer" 2>/dev/null | grep -q '[<,]UP[,>]'; do
		attempts=$((attempts + 1))
		[ "$attempts" -le "${MIRROR_ATTACH_WAIT_SECONDS:-300}" ] || fail capture-failed "the mirror was not attached in time"
		sleep 1
	done
	left=$(remaining)
	[ "$left" -gt 0 ] || exit 0
	# Header-only output unless the template opted into payload decoding.
	quiet=-q
	[ "${MIRROR_CAPTURE_PAYLOAD:-false}" != true ] || quiet=
	# timeout exits 124 at the approved expiry. tcpdump drops to nobody after
	# opening the capture socket.
	exec timeout "$left" tcpdump -Z nobody -p -n -l -e $quiet -i "$peer" -s "${MIRROR_SNAPLEN:?}" -c "${MIRROR_MAX_PACKETS:?}" -- ${MIRROR_FILTER:+"$MIRROR_FILTER"}
}

teardown() {
	require_env
	check_scan
	tpid=$(target_pid) || exit 1
	case "$tpid" in
	"") verified "the target network namespace is gone" ;;
	# A namespace that lost the approved IP may still hold the filters, so
	# this is never treated as proof of absence.
	recreated) fail teardown-unverifiable "the target Pod runs but no namespace of it owns the approved Pod IP; an operator must inspect the Node" ;;
	esac
	pin_target
	verify_pinned_target
	detach
	verify_detached
	verified "no filter with the operation cookie and no mirror device remain in the target network namespace"
}

# verified reports a successful teardown, also as termination message for
# the controller's audit record, and ends the script.
verified() {
	log teardown-verified "$1"
	printf '%s\n' "$1" >/dev/termination-log 2>/dev/null || true
	exit 0
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
