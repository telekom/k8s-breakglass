// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The helper is exercised against a fake host: a fake /proc tree whose
// ns/net links point to plain files standing in for network namespaces, and
// stub nsenter, ip and tc commands that read and write per-namespace state
// files. The pinned descriptors (/proc/self/fd/N) stay real, so the tests run
// on Linux only.
const (
	helperTargetUID  = "11111111-aaaa-4bbb-8ccc-000000000001"
	helperCaptureUID = "22222222-aaaa-4bbb-8ccc-000000000002"
	helperTargetIP   = "10.244.0.7"
	helperCaptureIP  = "10.244.0.9"
	helperVeth       = "bgm0123456789ab"
)

var helperStubs = map[string]string{
	// nsenter --net=REF -- CMD...: run CMD with NS set to the namespace file.
	"nsenter": `#!/bin/sh
ref=${1#--net=}
shift 2
NS=$(readlink -f "$ref") || exit 1
[ -f "$NS" ] || { echo "nsenter: cannot open $ref" >&2; exit 1; }
# The hook stays until it succeeds once.
if [ -f "$NS.on-enter" ] && sh "$NS.on-enter"; then rm -f "$NS.on-enter"; fi
export NS
exec "$@"`,
	"ip": `#!/bin/sh
echo "ip $*" >> "$STATE/calls"
if [ "${1:-}" = -o ]; then shift; fi
case "$1 $2" in
"addr show") cat "$NS.addrs" 2>/dev/null; exit 0 ;;
"link show")
	[ -n "${3:-}" ] || { cat "$NS".link.* 2>/dev/null; exit 0; }
	dev=$4
	[ -e "$NS.link.$dev" ] && { cat "$NS.link.$dev"; exit 0; }
	echo "Device \"$dev\" does not exist." >&2
	exit 1 ;;
"link add")
	# link add name VETH type veth peer name PEER netns REF
	: >"$NS.link.$4"
	: >"$(readlink -f "${11}").link.$9"
	exit 0 ;;
"link del") rm -f "$NS.link.$3"; exit 0 ;;
"link set")
	# link set dev DEV ... alias ALIAS records the alias like ip -o shows it.
	case " $* " in *" alias "*) alias=${*##* alias }; printf '\\    alias %s\n' "${alias%% *}" >>"$NS.link.$4" ;; esac
	exit 0 ;;
esac
exit 0`,
	"tc": `#!/bin/sh
echo "tc $*" >> "$STATE/calls"
case "$1 $2" in
"filter show") cat "$NS.filters.$4.$5" 2>/dev/null; exit 0 ;;
"filter del") rm -f "$NS.filters.$4.$5"; exit 0 ;;
"qdisc show") cat "$NS.qdiscs.$4" 2>/dev/null || echo "qdisc noqueue 0: root"; exit 0 ;;
esac
exit 0`,
}

type helperHost struct {
	t   *testing.T
	dir string
	env []string
}

// newHelperHost builds a fake host with PID 1 in the host namespace, the
// target Pod (PID 100) and the capture Pod (PID 200) in their namespaces.
func newHelperHost(t *testing.T) *helperHost {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the helper pins real /proc/self/fd descriptors")
	}
	for _, tool := range []string{"sh", "stat", "readlink"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required", tool)
		}
	}
	dir := t.TempDir()
	h := &helperHost{t: t, dir: dir}
	for _, sub := range []string{"bin", "ns", "proc", "run"} {
		require.NoError(t, os.Mkdir(filepath.Join(dir, sub), 0o755))
	}
	for name, body := range helperStubs {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "bin", name), []byte(body+"\n"), 0o755))
	}
	h.namespace("host", "1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 172.18.0.2/16 scope global eth0", "eth0")
	h.namespace("target", "1: lo    inet 127.0.0.1/8 scope host lo\n3: eth0    inet "+helperTargetIP+"/24 scope global eth0", "eth0")
	h.namespace("capture", "1: lo    inet 127.0.0.1/8 scope host lo\n3: eth0    inet "+helperCaptureIP+"/24 scope global eth0", "eth0")
	h.process(1, "0::/init.scope", "host")
	h.process(100, "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod"+strings.ReplaceAll(helperTargetUID, "-", "_")+".slice/cri-containerd-a.scope", "target")
	h.process(200, "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod"+strings.ReplaceAll(helperCaptureUID, "-", "_")+".slice/cri-containerd-b.scope", "capture")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "proc", "sys", "net", "ipv6"), 0o755))
	h.env = append(os.Environ(),
		"PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"),
		"STATE="+dir, "MIRROR_PROC_ROOT="+filepath.Join(dir, "proc"), "MIRROR_RUN_DIR="+filepath.Join(dir, "run"),
		"MIRROR_OPERATION=op", "MIRROR_INTERFACE=eth0", "MIRROR_VETH="+helperVeth,
		"MIRROR_COOKIE=0123456789abcdef0123456789abcdef", "MIRROR_PREF=50001", "MIRROR_RATE_MBIT=10",
		"MIRROR_POD_UID="+helperTargetUID, "MIRROR_POD_IP="+helperTargetIP,
		"MIRROR_CAPTURE_POD_UID="+helperCaptureUID, "MIRROR_CAPTURE_POD_IP="+helperCaptureIP,
		"MIRROR_EXPIRES_UNIX="+strconv.FormatInt(time.Now().Add(3*time.Second).Unix(), 10))
	return h
}

// namespace creates a namespace file with its addresses and links.
func (h *helperHost) namespace(name, addrs string, links ...string) {
	h.t.Helper()
	path := filepath.Join(h.dir, "ns", name)
	require.NoError(h.t, os.WriteFile(path, nil, 0o644))
	require.NoError(h.t, os.WriteFile(path+".addrs", []byte(addrs+"\n"), 0o644))
	for _, link := range links {
		require.NoError(h.t, os.WriteFile(path+".link."+link, []byte(helperLink(3, link)), 0o644))
	}
}

// helperLink renders an "ip -o link show" line.
func helperLink(index int, name string) string {
	return fmt.Sprintf("%d: %s: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default \\    link/ether 02:00:00:00:00:%02x brd ff:ff:ff:ff:ff:ff\n", index, name, index)
}

// ownVeth marks the namespace's mirror device as this operation's.
func (h *helperHost) ownVeth(namespace string) {
	h.t.Helper()
	file, err := os.OpenFile(filepath.Join(h.dir, "ns", namespace+".link."+helperVeth), os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(h.t, err)
	_, err = file.WriteString("\\    alias bgmirror:0123456789abcdef0123456789abcdef\n")
	require.NoError(h.t, errors.Join(err, file.Close()))
}

// process places a fake PID with a cgroup in a namespace.
func (h *helperHost) process(pid int, cgroup, namespace string) {
	h.t.Helper()
	dir := filepath.Join(h.dir, "proc", strconv.Itoa(pid))
	require.NoError(h.t, os.MkdirAll(filepath.Join(dir, "ns"), 0o755))
	require.NoError(h.t, os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup+"\n"), 0o644))
	link := filepath.Join(dir, "ns", "net")
	_ = os.Remove(link)
	require.NoError(h.t, os.Symlink(filepath.Join(h.dir, "ns", namespace), link))
}

// run executes the real helper and returns its exit code and output.
func (h *helperHost) run(mode string) (int, string) {
	h.t.Helper()
	script := filepath.Join(h.dir, "traffic_mirror.sh")
	require.NoError(h.t, os.WriteFile(script, []byte(trafficMirrorScript), 0o644))
	command := exec.CommandContext(h.t.Context(), "sh", script, mode)
	command.Env = h.env
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	err := command.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), output.String()
	}
	require.NoError(h.t, err)
	return 0, output.String()
}

func (h *helperHost) calls() string {
	data, _ := os.ReadFile(filepath.Join(h.dir, "calls"))
	return string(data)
}

func TestTrafficMirrorHelperTeardownVerifiesCleanTarget(t *testing.T) {
	h := newHelperHost(t)
	h.namespace("target", "3: eth0    inet "+helperTargetIP+"/24 scope global eth0", "eth0", helperVeth)
	h.ownVeth("target")
	code, output := h.run("teardown")
	require.Equal(t, 0, code, output)
	require.Contains(t, output, "teardown-verified")
	require.Contains(t, h.calls(), "ip link del "+helperVeth, "the mirror device is removed")
}

func TestTrafficMirrorHelperTeardownUnverifiableWhenIPMoved(t *testing.T) {
	h := newHelperHost(t)
	// The Pod still runs, but its namespace no longer owns the approved IP.
	h.namespace("target", "3: eth0    inet 10.244.0.99/24 scope global eth0", "eth0", helperVeth)
	code, output := h.run("teardown")
	require.Equal(t, 1, code, output)
	require.Contains(t, output, "teardown-unverifiable")
	require.NotContains(t, output, "teardown-verified")
}

func TestTrafficMirrorHelperTeardownFailsOnInspectionError(t *testing.T) {
	h := newHelperHost(t)
	// The target process exists, but its namespace cannot be entered.
	require.NoError(t, os.Remove(filepath.Join(h.dir, "ns", "target")))
	code, output := h.run("teardown")
	require.Equal(t, 1, code, output)
	require.Contains(t, output, "inspect-failed")
	require.NotContains(t, output, "teardown-verified")
}

func TestTrafficMirrorHelperTeardownRepeatsIdentityChecks(t *testing.T) {
	h := newHelperHost(t)
	// A host-network Pod: its process owns the IP but lives in the host
	// namespace. The pinned-namespace check must refuse to touch the host.
	h.namespace("host", "2: eth0    inet "+helperTargetIP+"/24 scope global eth0", "eth0", helperVeth)
	h.process(100, "0::/kubepods/pod"+helperTargetUID+"/a", "host")
	code, output := h.run("teardown")
	require.Equal(t, 1, code, output)
	require.Contains(t, output, "the target Pod uses the host network")
	require.NotContains(t, h.calls(), "ip link del", "nothing is removed from the host namespace")
}

func TestTrafficMirrorHelperRejectsReusedPID(t *testing.T) {
	h := newHelperHost(t)
	// The scan enters PID 100's namespace; right after, the PID is reused by
	// a process of another Pod before the namespace is pinned.
	reuse := "printf '0::/kubepods/podother/x\\n' >" + filepath.Join(h.dir, "proc", "100", "cgroup")
	h.namespace("target", "3: eth0    inet "+helperTargetIP+"/24 scope global eth0", "eth0", helperVeth)
	require.NoError(t, os.WriteFile(filepath.Join(h.dir, "ns", "target.on-enter"), []byte(reuse+"\n"), 0o644))
	code, output := h.run("teardown")
	require.Equal(t, 1, code, output)
	require.Contains(t, output, "no longer belongs to Pod")
	require.NotContains(t, h.calls(), "ip link del")
}

func TestTrafficMirrorHelperAttachRefusesWrongCaptureNamespace(t *testing.T) {
	for name, tc := range map[string]struct {
		setup  func(h *helperHost)
		expect string
	}{
		"host namespace": {func(h *helperHost) {
			h.namespace("host", "2: eth0    inet "+helperCaptureIP+"/24 scope global eth0", "eth0")
			h.process(200, "0::/kubepods/pod"+helperCaptureUID+"/b", "host")
		}, "the capture Pod uses the host network"},
		"target namespace": {func(h *helperHost) {
			h.namespace("target", "3: eth0    inet "+helperTargetIP+"/24 scope global eth0\n4: eth1    inet "+helperCaptureIP+"/24", "eth0")
			h.process(200, "0::/kubepods/pod"+helperCaptureUID+"/b", "target")
		}, "the capture Pod shares the target network namespace"},
		"missing capture IP": {func(h *helperHost) {
			h.namespace("capture", "3: eth0    inet 10.244.0.50/24 scope global eth0", "eth0")
		}, "the capture Pod is not running with its approved IP"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHelperHost(t)
			tc.setup(h)
			code, output := h.run("attach")
			require.Equal(t, 1, code, output)
			require.Contains(t, output, tc.expect)
			require.NotContains(t, h.calls(), "ip link add", "no mirror device is created")
			require.NotContains(t, h.calls(), "mirred", "no mirror filter is attached")
		})
	}
}

func TestTrafficMirrorHelperAttachSkipsAddrgenWithoutIPv6(t *testing.T) {
	for name, ipv6 := range map[string]bool{"with IPv6": true, "without IPv6": false} {
		t.Run(name, func(t *testing.T) {
			h := newHelperHost(t)
			if !ipv6 {
				require.NoError(t, os.RemoveAll(filepath.Join(h.dir, "proc", "sys", "net", "ipv6")))
			}
			code, output := h.run("attach")
			require.Equal(t, 0, code, output)
			require.Contains(t, output, "mirror-expired", "the agent detaches at the approved expiry")
			calls := h.calls()
			require.Contains(t, calls, "ip link add name "+helperVeth+" type veth peer name bgmirror0 netns /proc/self/fd/4")
			// continue keeps foreign filters at higher preferences classifying.
			require.Contains(t, calls, "mirred egress mirror dev "+helperVeth+" continue cookie ")
			require.Contains(t, calls, "tc filter add dev "+helperVeth+" ingress pref 1 protocol all basic action drop")
			if ipv6 {
				require.Contains(t, calls, "ip link set dev "+helperVeth+" addrgenmode none arp off")
			} else {
				require.Contains(t, calls, "ip link set dev "+helperVeth+" arp off")
				require.NotContains(t, calls, "addrgenmode", "nodes booted with ipv6.disable=1 reject addrgenmode")
			}
			// The capture end comes up last, after every mirror filter.
			require.Greater(t, strings.LastIndex(calls, "ip link set bgmirror0 up"), strings.LastIndex(calls, "mirred"))
		})
	}
}

func TestTrafficMirrorHelperTeardownFindsRenamedInterface(t *testing.T) {
	h := newHelperHost(t)
	// eth0 was renamed to net1 after the attach; its mirror filters moved along.
	h.namespace("target", "3: net1    inet "+helperTargetIP+"/24 scope global net1", "net1", helperVeth)
	h.ownVeth("target")
	filter := "filter protocol all pref 50001 basic chain 0 handle 0x1 \n\taction order 1: mirred (Egress Mirror to device " +
		helperVeth + ") continue\n\tcookie 0123456789abcdef0123456789abcdef\n"
	for _, hook := range []string{"ingress", "egress"} {
		require.NoError(t, os.WriteFile(filepath.Join(h.dir, "ns", "target.filters.net1."+hook), []byte(filter), 0o644))
	}
	code, output := h.run("teardown")
	require.Equal(t, 0, code, output)
	require.Contains(t, output, "teardown-verified")
	for _, hook := range []string{"ingress", "egress"} {
		require.Contains(t, h.calls(), "tc filter del dev net1 "+hook+" pref 50001 handle 0x1", "the renamed interface keeps no mirror")
	}
}

func TestTrafficMirrorHelperAttachDetectsRecreatedInterface(t *testing.T) {
	h := newHelperHost(t)
	// After the attach, eth0 is deleted and created again: same name, new
	// ifindex and MAC, and none of the mirror filters.
	recreate := "[ -e " + filepath.Join(h.dir, "run", "attached") + " ] && printf '%s' '" + helperLink(7, "eth0") + "' >" +
		filepath.Join(h.dir, "ns", "target.link.eth0")
	require.NoError(t, os.WriteFile(filepath.Join(h.dir, "ns", "target.on-enter"), []byte(recreate+"\n"), 0o644))
	code, output := h.run("attach")
	require.Equal(t, 1, code, output)
	require.Contains(t, output, "interface-changed")
	require.NotContains(t, output, "mirror-expired")
	require.NotContains(t, h.calls(), "ip link del "+helperVeth, "the capture keeps its device, so the cause is reported first")
}

func TestTrafficMirrorHelperAttachRefusesUnreadableInterfaceIdentity(t *testing.T) {
	h := newHelperHost(t)
	// eth0 exists, but ip prints nothing for it: an empty identity would
	// later "match" a missing interface.
	require.NoError(t, os.WriteFile(filepath.Join(h.dir, "ns", "target.link.eth0"), nil, 0o644))
	code, output := h.run("attach")
	require.Equal(t, 1, code, output)
	require.Contains(t, output, "inspect-failed")
	require.NotContains(t, h.calls(), "mirred", "no mirror filter is attached")
}

func TestTrafficMirrorHelperAttachCopiesSourceMTU(t *testing.T) {
	h := newHelperHost(t)
	// A jumbo-frame source: a mirror device at the default 1500 would drop
	// every larger copy before the capture.
	jumbo := strings.Replace(helperLink(3, "eth0"), "mtu 1500", "mtu 9000", 1)
	require.NoError(t, os.WriteFile(filepath.Join(h.dir, "ns", "target.link.eth0"), []byte(jumbo), 0o644))
	code, output := h.run("attach")
	require.Equal(t, 0, code, output)
	calls := h.calls()
	require.Contains(t, calls, "ip link set dev "+helperVeth+" addrgenmode none arp off mtu 9000")
	require.Contains(t, calls, "ip link set dev bgmirror0 addrgenmode none arp off mtu 9000")
	require.Less(t, strings.Index(calls, "mtu 9000"), strings.Index(calls, "ip link set bgmirror0 up"), "the MTU is set before the capture side comes up")
}

func TestTrafficMirrorHelperRescansWhenAPodProcessExits(t *testing.T) {
	ns := func(h *helperHost) string { return filepath.Join(h.dir, "proc", "10", "ns", "net") }
	for name, exit := range map[string]func(h *helperHost){
		// PID 10 is gone right after the scan inspected its namespace.
		"exited after the scan": func(h *helperHost) {
			hook := "rm -rf " + filepath.Join(h.dir, "proc", "10")
			require.NoError(h.t, os.WriteFile(filepath.Join(h.dir, "ns", "target.on-enter"), []byte(hook+"\n"), 0o644))
		},
		// PID 10 is a zombie after the scan: /proc/10 stays, its namespace
		// link does not resolve any more and its state is Z.
		"zombie after the scan": func(h *helperHost) {
			hook := "ln -sfn " + filepath.Join(h.dir, "ns", "gone") + " " + ns(h) + " && printf 'State:\\tZ (zombie)\\n' >" +
				filepath.Join(h.dir, "proc", "10", "status")
			require.NoError(h.t, os.WriteFile(filepath.Join(h.dir, "ns", "target.on-enter"), []byte(hook+"\n"), 0o644))
		},
		// PID 10 is already a zombie when the scan reaches it.
		"zombie during the scan": func(h *helperHost) {
			require.NoError(h.t, os.Remove(ns(h)))
			require.NoError(h.t, os.Symlink(filepath.Join(h.dir, "ns", "gone"), ns(h)))
			require.NoError(h.t, os.WriteFile(filepath.Join(h.dir, "proc", "10", "status"), []byte("State:\tZ (zombie)\n"), 0o644))
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHelperHost(t)
			h.namespace("target", "3: eth0    inet "+helperTargetIP+"/24 scope global eth0", "eth0", helperVeth)
			h.ownVeth("target")
			// PID 10 of the target Pod is scanned first, like a short-lived
			// process the Pod forks.
			h.process(10, "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod"+strings.ReplaceAll(helperTargetUID, "-", "_")+".slice/cri-containerd-c.scope", "target")
			exit(h)
			code, output := h.run("teardown")
			require.Equal(t, 0, code, output)
			require.Contains(t, output, "teardown-verified")
		})
	}
}

func TestTrafficMirrorHelperNeverDeletesAForeignDevice(t *testing.T) {
	for mode, reason := range map[string]string{"teardown": "teardown-unverifiable", "attach": "device-conflict"} {
		t.Run(mode, func(t *testing.T) {
			h := newHelperHost(t)
			// Another tool owns a device of the mirror device's name.
			h.namespace("target", "3: eth0    inet "+helperTargetIP+"/24 scope global eth0", "eth0", helperVeth)
			code, output := h.run(mode)
			require.Equal(t, 1, code, output)
			require.Contains(t, output, "does not own")
			require.Contains(t, output, `"event":"`+reason+`"`)
			require.NotContains(t, h.calls(), "ip link del", "a foreign device is never deleted")
			require.NotContains(t, h.calls(), "ip link add", "no mirror is attached next to it")
		})
	}
}

func TestTrafficMirrorHelperAttachRefusesInterfaceReplacedDuringAttach(t *testing.T) {
	for name, tc := range map[string]struct {
		when, never string
	}{
		// Re-created once the mirror device exists: eth0 is never changed.
		"before the source is changed": {"[ -e ns/target.link." + helperVeth + " ]", "tc qdisc add dev eth0"},
		// Re-created after the filters were added: the capture never starts.
		"before the capture starts": {"grep -q 'tc filter add dev eth0 egress' calls", "ip link set bgmirror0 up"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHelperHost(t)
			replace := "cd " + h.dir + " && " + tc.when + " && printf '%s' '" + helperLink(7, "eth0") + "' >ns/target.link.eth0"
			require.NoError(t, os.WriteFile(filepath.Join(h.dir, "ns", "target.on-enter"), []byte(replace+"\n"), 0o644))
			code, output := h.run("attach")
			require.Equal(t, 1, code, output)
			require.Contains(t, output, "interface-changed")
			calls := h.calls()
			require.NotContains(t, calls, tc.never)
			require.NotContains(t, calls, "ip link set bgmirror0 up", "the capture never starts")
		})
	}
}

func TestTrafficMirrorHelperTeardownFailsOnUnreadableCgroup(t *testing.T) {
	h := newHelperHost(t)
	h.namespace("target", "3: eth0    inet "+helperTargetIP+"/24 scope global eth0", "eth0", helperVeth)
	// The target's cgroup cannot be read (a directory makes grep fail), so
	// the scan cannot tell whether PID 100 belongs to the Pod.
	cgroup := filepath.Join(h.dir, "proc", "100", "cgroup")
	require.NoError(t, os.Remove(cgroup))
	require.NoError(t, os.Mkdir(cgroup, 0o755))
	code, output := h.run("teardown")
	require.Equal(t, 1, code, output)
	require.Contains(t, output, "inspect-failed")
	require.NotContains(t, output, "teardown-verified", "a read error is never proof that the target is gone")
}

func TestTrafficMirrorHelperReportsAMissingKernelFeature(t *testing.T) {
	h := newHelperHost(t)
	// The kernel lacks act_mirred: adding the mirror filter fails.
	stub := filepath.Join(h.dir, "bin", "tc")
	body, err := os.ReadFile(stub)
	require.NoError(t, err)
	missing := strings.Replace(string(body), `echo "tc $*" >> "$STATE/calls"`,
		`echo "tc $*" >> "$STATE/calls"
case "$*" in *mirred*) echo "Error: Cannot find action mirred" >&2; exit 2 ;; esac`, 1)
	require.NoError(t, os.WriteFile(stub, []byte(missing), 0o755))
	code, output := h.run("attach")
	require.Equal(t, 1, code, output)
	require.Contains(t, output, `"event":"unsupported-kernel"`)
	require.Contains(t, output, "act_mirred")
	require.NotContains(t, h.calls(), "ip link set bgmirror0 up", "the capture never starts")
}

func TestTrafficMirrorHelperReportsWhyClsactCannotBeAdded(t *testing.T) {
	for name, tc := range map[string]struct {
		setup           func(h *helperHost)
		event, detail   string
		triesToAddQdisc bool
	}{
		"legacy ingress qdisc": {func(h *helperHost) {
			require.NoError(h.t, os.WriteFile(filepath.Join(h.dir, "ns", "target.qdiscs.eth0"),
				[]byte("qdisc noqueue 0: root refcnt 2\nqdisc ingress ffff: parent ffff:fff1 ----------------\n"), 0o644))
		}, "qdisc-conflict", "qdisc ingress ffff:", false},
		"kernel without sch_ingress": {func(h *helperHost) {
			stub := filepath.Join(h.dir, "bin", "tc")
			body, err := os.ReadFile(stub)
			require.NoError(h.t, err)
			missing := strings.Replace(string(body), `echo "tc $*" >> "$STATE/calls"`, `echo "tc $*" >> "$STATE/calls"
case "$*" in "qdisc add dev eth0 clsact") echo "Error: Specified qdisc kind is unknown." >&2; exit 2 ;; esac`, 1)
			require.NoError(h.t, os.WriteFile(stub, []byte(missing), 0o755))
		}, "unsupported-kernel", "Error: Specified qdisc kind is unknown.", true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHelperHost(t)
			tc.setup(h)
			code, output := h.run("attach")
			require.Equal(t, 1, code, output)
			require.Contains(t, output, `"event":"`+tc.event+`"`)
			require.Contains(t, output, tc.detail, "the failure carries the tc output")
			calls := h.calls()
			require.Equal(t, tc.triesToAddQdisc, strings.Contains(calls, "tc qdisc add dev eth0 clsact"))
			require.NotContains(t, calls, "tc filter add dev eth0", "no mirror filter is attached")
		})
	}
}
