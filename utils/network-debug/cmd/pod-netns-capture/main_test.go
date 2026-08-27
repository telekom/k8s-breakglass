// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testUID = "12345678-1234-4abc-8def-1234567890ab"

func TestParseOptionsBoundsAndIdentity(t *testing.T) {
	t.Parallel()
	valid, err := parseOptions([]string{
		"--pod-uid", testUID,
		"--output", "capture.pcap",
		"--interface", "eth0.42",
		"--duration", "300",
		"--count", "10000",
		"--snaplen", "256",
		"--filter", "tcp port 443",
	})
	if err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
	if valid.podUID != testUID || valid.duration != 300 || valid.count != 10000 || valid.snaplen != 256 {
		t.Fatalf("unexpected parsed options: %#v", valid)
	}

	tests := []struct {
		name string
		args []string
	}{
		{name: "no UID", args: []string{"--output", "capture.pcap"}},
		{name: "uppercase UID", args: []string{"--pod-uid", strings.ToUpper(testUID), "--output", "capture.pcap"}},
		{name: "UID suffix", args: []string{"--pod-uid", testUID + "0", "--output", "capture.pcap"}},
		{name: "PID option", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--pid", "42"}},
		{name: "pod name option", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--pod", "target"}},
		{name: "node option", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--node", "worker"}},
		{name: "runtime option", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--runtime", "containerd"}},
		{name: "tcpdump option", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--tcpdump", "/tmp/tool"}},
		{name: "command option", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--command", "sh"}},
		{name: "proc root option", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--proc-root", "/host/proc"}},
		{name: "work root option", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--work-root", "/host"}},
		{name: "duplicate", args: []string{"--pod-uid", testUID, "--pod-uid", testUID, "--output", "capture.pcap"}},
		{name: "zero duration", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--duration", "0"}},
		{name: "leading zero", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--count", "01"}},
		{name: "oversized snaplen", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--snaplen", "257"}},
		{name: "interface traversal", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--interface", "../eth0"}},
		{name: "output traversal", args: []string{"--pod-uid", testUID, "--output", "../capture.pcap"}},
		{name: "absolute output", args: []string{"--pod-uid", testUID, "--output", "/work/capture.pcap"}},
		{name: "filter newline", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--filter", "tcp\nport 80"}},
		{name: "filter too long", args: []string{"--pod-uid", testUID, "--output", "capture.pcap", "--filter", strings.Repeat("x", maxFilterBytes+1)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseOptions(test.args); err == nil {
				t.Fatalf("unsafe options accepted: %v", test.args)
			}
		})
	}
}

func TestMatchTargetCgroupSupportedLayouts(t *testing.T) {
	t.Parallel()
	containerID := strings.Repeat("a", 64)
	escaped := strings.ReplaceAll(testUID, "-", `\x2d`)
	underscored := strings.ReplaceAll(testUID, "-", "_")
	tests := []struct {
		name   string
		path   string
		family string
	}{
		{name: "cgroup v2 guaranteed", path: "0::/kubepods/pod" + testUID + "/" + containerID, family: "cgroupfs-cri"},
		{name: "cgroup v1 burstable", path: "11:memory:/kubepods/burstable/pod" + testUID + "/" + containerID, family: "cgroupfs-cri"},
		{name: "private cgroup namespace", path: "0::/../../../kubepods/burstable/pod" + testUID + "/" + containerID, family: "cgroupfs-cri"},
		{name: "private cgroup namespace same qos", path: "0::/../../pod" + testUID + "/" + containerID, family: "cgroupfs-cri"},
		{name: "private cgroup namespace other qos", path: "0::/../../../burstable/pod" + testUID + "/" + containerID, family: "cgroupfs-cri"},
		{name: "containerd systemd underscore", path: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + underscored + ".slice/cri-containerd-" + containerID + ".scope", family: "cri-containerd"},
		{name: "containerd systemd inline", path: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + underscored + ".slice:cri-containerd:" + containerID + ".scope", family: "cri-containerd"},
		{name: "containerd systemd inline under system slice", path: "0::/system.slice/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + underscored + ".slice:cri-containerd:" + containerID + ".scope", family: "cri-containerd"},
		{name: "containerd systemd inline system slice qos", path: "0::/system.slice/kubepods-burstable.slice/kubepods-burstable-pod" + underscored + ".slice:cri-containerd:" + containerID + ".scope", family: "cri-containerd"},
		{name: "crio systemd escaped", path: "0::/kubepods.slice/kubepods-pod" + escaped + ".slice/crio-" + containerID + ".scope", family: "crio"},
		{name: "docker systemd", path: "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + underscored + ".slice/docker-" + containerID + ".scope", family: "docker"},
		{name: "private systemd same qos", path: "0::/../../kubepods-burstable-pod" + underscored + ".slice/cri-containerd-" + containerID + ".scope", family: "cri-containerd"},
		{name: "private systemd other qos", path: "0::/../../../kubepods-besteffort.slice/kubepods-besteffort-pod" + underscored + ".slice/cri-containerd-" + containerID + ".scope", family: "cri-containerd"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			matched, family, err := matchTargetCgroup([]byte(test.path+"\n"), testUID)
			if err != nil || !matched || family != test.family {
				t.Fatalf("matchTargetCgroup() = %v, %q, %v; want true, %q, nil", matched, family, err, test.family)
			}
		})
	}
}

func TestMatchTargetCgroupRejectsConfusableAndUnknownLayouts(t *testing.T) {
	t.Parallel()
	containerID := strings.Repeat("b", 64)
	tests := []string{
		"0::/kubepods/pod" + testUID + "-decoy/" + containerID,
		"0::/kubepods/prefix-pod" + testUID + "/" + containerID,
		"0::/kubepods/burstable/pod" + testUID + "/libpod-" + containerID + ".scope",
		"0::/vendor.slice/pod" + testUID + "/" + containerID,
		"malformed/pod" + testUID + "/" + containerID,
		"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + testUID + ".slice/cri-containerd-" + containerID + ".scope",
		"0::/kubepods/burstable/pod" + strings.ToUpper(testUID) + "/" + containerID,
		"0::/kubepods/../burstable/pod" + testUID + "/" + containerID,
		"0::/../../../../../../../../../../../../../../../../../kubepods/pod" + testUID + "/" + containerID,
	}
	for _, cgroup := range tests {
		t.Run(cgroup, func(t *testing.T) {
			t.Parallel()
			matched, _, err := matchTargetCgroup([]byte(cgroup+"\n"), testUID)
			if matched || !errors.Is(err, errUnsupportedLayout) {
				t.Fatalf("confusable/unknown cgroup accepted: matched=%v err=%v", matched, err)
			}
		})
	}

	matched, _, err := matchTargetCgroup([]byte("0::/kubepods/burstable/pod00000000-0000-4000-8000-000000000000/"+containerID+"\n"), testUID)
	if err != nil || matched {
		t.Fatalf("unrelated pod was not ignored: matched=%v err=%v", matched, err)
	}
}

func TestProcScannerSelectsExactPodAndRejectsMultipleNetns(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	netnsA := filepath.Join(root, "netns-a")
	netnsB := filepath.Join(root, "netns-b")
	writeFixtureFile(t, netnsA, "namespace-a")
	writeFixtureFile(t, netnsB, "namespace-b")
	containerID := strings.Repeat("c", 64)
	addFakeProcess(t, root, 101, testUID, containerID, netnsA, "111")
	addFakeProcess(t, root, 102, testUID, containerID, netnsA, "222")
	addFakeProcess(t, root, 103, "00000000-0000-4000-8000-000000000000", containerID, netnsB, "333")

	scanner := procScanner{root: root}
	target, err := scanner.scanTarget(testUID)
	if err != nil {
		t.Fatalf("scanTarget() error = %v", err)
	}
	if len(target.processes) != 2 || target.processes[0].pid != 101 || target.processes[1].pid != 102 {
		t.Fatalf("unexpected exact candidates: %#v", target.processes)
	}

	processNetns := filepath.Join(root, "102", "ns", "net")
	if err := os.Remove(processNetns); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(netnsB, processNetns); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.scanTarget(testUID); !errors.Is(err, errTargetAmbiguous) {
		t.Fatalf("multiple netns error = %v, want %v", err, errTargetAmbiguous)
	}
}

func TestProcScannerRejectsUIDSubstringDecoy(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	netns := filepath.Join(root, "netns")
	writeFixtureFile(t, netns, "namespace")
	containerID := strings.Repeat("e", 64)
	addFakeProcess(t, root, 301, testUID, containerID, netns, "555")
	addFakeProcess(t, root, 302, testUID+"0", containerID, netns, "556")
	if _, err := (procScanner{root: root}).scanTarget(testUID); !errors.Is(err, errUnsupportedLayout) {
		t.Fatalf("substring decoy error = %v, want %v", err, errUnsupportedLayout)
	}
}

func TestRevalidateRejectsPIDReuseAndTargetDisappearance(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	netns := filepath.Join(root, "netns")
	writeFixtureFile(t, netns, "namespace")
	containerID := strings.Repeat("d", 64)
	addFakeProcess(t, root, 201, testUID, containerID, netns, "444")
	scanner := procScanner{root: root}
	target, err := scanner.scanTarget(testUID)
	if err != nil {
		t.Fatal(err)
	}
	anchor := target.processes[0]
	writeFixtureFile(t, filepath.Join(root, "201", "stat"), fakeStat(201, "reused process", "445"))
	if err := scanner.revalidate(anchor, testUID, target.namespace); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("PID reuse error = %v", err)
	}

	if err := os.RemoveAll(filepath.Join(root, "201")); err != nil {
		t.Fatal(err)
	}
	if err := scanner.revalidate(anchor, testUID, target.namespace); !errors.Is(err, errTargetMissing) {
		t.Fatalf("disappearance error = %v, want %v", err, errTargetMissing)
	}
}

func TestRevalidateAcceptsStableTargetAndRejectsCgroupChange(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	netns := filepath.Join(root, "netns")
	writeFixtureFile(t, netns, "namespace")
	containerID := strings.Repeat("f", 64)
	addFakeProcess(t, root, 211, testUID, containerID, netns, "600")
	scanner := procScanner{root: root}
	target, err := scanner.scanTarget(testUID)
	if err != nil {
		t.Fatal(err)
	}
	anchor := target.processes[0]
	if err := scanner.revalidate(anchor, testUID, target.namespace); err != nil {
		t.Fatalf("stable target rejected: %v", err)
	}
	writeFixtureFile(t, filepath.Join(root, "211", "cgroup"), "0::/kubepods/pod"+testUID+"/"+strings.Repeat("1", 64)+"\n")
	if err := scanner.revalidate(anchor, testUID, target.namespace); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("changed cgroup error = %v", err)
	}
}

func TestPCAPInspectionEnforcesPacketSnaplenAndSizeBounds(t *testing.T) {
	t.Parallel()
	pcap := makePCAP(t, binary.LittleEndian, 64, [][]byte{{1, 2, 3}, {4, 5}})
	count, err := pcapPacketCount(bytes.NewReader(pcap), 2, 64)
	if err != nil || count != 2 {
		t.Fatalf("pcapPacketCount() = %d, %v", count, err)
	}
	if _, err := pcapPacketCount(bytes.NewReader(pcap), 1, 64); err == nil {
		t.Fatal("packet limit was not enforced")
	}
	if _, err := pcapPacketCount(bytes.NewReader(pcap), 2, 128); err == nil {
		t.Fatal("snaplen mismatch was not enforced")
	}
	if _, err := pcapPacketCount(bytes.NewReader(pcap[:len(pcap)-1]), 2, 64); err == nil {
		t.Fatal("truncated payload was accepted")
	}
	if int64(len(pcap)) > captureSizeBound(2, 64) {
		t.Fatalf("valid pcap exceeds computed bound: %d", len(pcap))
	}
}

func TestCaptureSummaryIsStableAndOmitsFilterPayload(t *testing.T) {
	t.Parallel()
	opts := options{
		podUID: testUID, interfaceName: "eth0", duration: 10, count: 20,
		snaplen: 128, filter: "host 192.0.2.10 and tcp port 443", output: "capture.pcap",
	}
	var first bytes.Buffer
	var second bytes.Buffer
	if err := outputSummary(&first, opts, 7, 1024, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := outputSummary(&second, opts, 7, 1024, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("capture summary is not deterministic")
	}
	if strings.Contains(first.String(), opts.filter) || strings.Contains(first.String(), "192.0.2.10") {
		t.Fatalf("capture summary leaked the packet filter: %q", first.String())
	}
	for _, field := range []string{"capture_status complete", "packet_count 7", "bytes 1024", "sha256 " + strings.Repeat("a", 64)} {
		if !strings.Contains(first.String(), field+"\n") {
			t.Fatalf("summary lacks %q: %q", field, first.String())
		}
	}
}

func TestHashAndInspectCapture(t *testing.T) {
	t.Parallel()
	opts := options{count: 2, snaplen: 64}
	contents := makePCAP(t, binary.LittleEndian, opts.snaplen, [][]byte{{1, 2, 3}})
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	packets, size, hash, err := hashAndInspectCapture(file, opts)
	if err != nil {
		t.Fatal(err)
	}
	wantedHash := fmt.Sprintf("%x", sha256.Sum256(contents))
	if packets != 1 || size != int64(len(contents)) || hash != wantedHash {
		t.Fatalf("hashAndInspectCapture() = %d, %d, %q; want 1, %d, %q", packets, size, hash, len(contents), wantedHash)
	}
}

func TestHashAndInspectCaptureRejectsOversizeAndMalformedFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	oversizedPath := filepath.Join(root, "oversized.pcap")
	if err := os.WriteFile(oversizedPath, bytes.Repeat([]byte{'x'}, int(captureSizeBound(1, 64)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	oversized, err := os.Open(oversizedPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hashAndInspectCapture(oversized, options{count: 1, snaplen: 64}); err == nil || !strings.Contains(err.Error(), "size bound") {
		t.Fatalf("oversized capture error = %v", err)
	}
	oversized.Close()

	malformedPath := filepath.Join(root, "malformed.pcap")
	if err := os.WriteFile(malformedPath, []byte("not a pcap"), 0o600); err != nil {
		t.Fatal(err)
	}
	malformed, err := os.Open(malformedPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hashAndInspectCapture(malformed, options{count: 1, snaplen: 64}); err == nil || !strings.Contains(err.Error(), "pcap header") {
		t.Fatalf("malformed capture error = %v", err)
	}
	malformed.Close()
	if _, _, _, err := hashAndInspectCapture(malformed, options{count: 1, snaplen: 64}); err == nil || !strings.Contains(err.Error(), "stat capture") {
		t.Fatalf("closed capture error = %v", err)
	}
}

func TestStableErrorsUsageAndSimpleBounds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		want string
	}{
		{err: errTargetMissing, want: "target pod is not present"},
		{err: errTargetAmbiguous, want: "ambiguous"},
		{err: errUnsupportedLayout, want: "unsupported"},
		{err: errors.New("specific failure"), want: "specific failure"},
	}
	for _, test := range tests {
		if got := stableError(test.err); !strings.Contains(got, test.want) {
			t.Fatalf("stableError(%v) = %q, want substring %q", test.err, got, test.want)
		}
	}
	var help bytes.Buffer
	usage(&help)
	if !strings.Contains(help.String(), "--pod-uid UID") {
		t.Fatalf("usage missing immutable UID contract: %q", help.String())
	}
	if duration := waitBound(3); duration != 3*time.Second {
		t.Fatalf("waitBound(3) = %v", duration)
	}
	for _, value := range []string{"", "0", "01", "-1", "abc"} {
		if _, ok := numericPID(value); ok {
			t.Fatalf("numericPID(%q) accepted", value)
		}
	}
}

func FuzzMatchTargetCgroup(f *testing.F) {
	f.Add("0::/kubepods/burstable/pod" + testUID + "/" + strings.Repeat("a", 64) + "\n")
	f.Add("0::/kubepods/burstable/pod" + testUID + "-decoy/" + strings.Repeat("b", 64) + "\n")
	f.Add("garbage\x00pod" + testUID)
	f.Fuzz(func(t *testing.T, cgroup string) {
		matched, family, err := matchTargetCgroup([]byte(cgroup), testUID)
		if matched {
			if err != nil || family == "" {
				t.Fatalf("matched cgroup lacks a supported runtime: family=%q err=%v", family, err)
			}
			if !containsUIDRepresentation(strings.ToLower(cgroup), uidRepresentations(testUID)) {
				t.Fatal("matched cgroup does not contain the exact target representation")
			}
		}
	})
}

func addFakeProcess(t *testing.T, root string, pid int, uid, containerID, netns, startTime string) {
	t.Helper()
	directory := filepath.Join(root, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(filepath.Join(directory, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(directory, "stat"), fakeStat(pid, "fixture ) process", startTime))
	writeFixtureFile(t, filepath.Join(directory, "cgroup"), "0::/kubepods/burstable/pod"+uid+"/"+containerID+"\n")
	if err := os.Link(netns, filepath.Join(directory, "ns", "net")); err != nil {
		t.Fatal(err)
	}
}

func fakeStat(pid int, command, startTime string) string {
	// Fields 3 through 21 contain 19 values; starttime is field 22.
	return fmt.Sprintf("%d (%s) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 %s 0 0\n", pid, command, startTime)
}

func writeFixtureFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func makePCAP(t *testing.T, order binary.ByteOrder, snaplen int, packets [][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	magic := uint32(0xa1b2c3d4)
	if err := binary.Write(&output, order, magic); err != nil {
		t.Fatal(err)
	}
	for _, value := range []uint16{2, 4} {
		if err := binary.Write(&output, order, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []uint32{0, 0, uint32(snaplen), 1} {
		if err := binary.Write(&output, order, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, packet := range packets {
		for _, value := range []uint32{0, 0, uint32(len(packet)), uint32(len(packet))} {
			if err := binary.Write(&output, order, value); err != nil {
				t.Fatal(err)
			}
		}
		output.Write(packet)
	}
	return output.Bytes()
}
