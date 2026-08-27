// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// pod-netns-capture resolves an immutable Kubernetes Pod UID through procfs,
// enters the unambiguous pod network namespace, and runs a bounded tcpdump.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultInterface = "any"
	defaultDuration  = 30
	defaultCount     = 1000
	defaultSnaplen   = 128
	maxDuration      = 300
	maxCount         = 10000
	minSnaplen       = 64
	maxSnaplen       = 256
	maxFilterBytes   = 256
	maxOutputBytes   = 64
	procRoot         = "/proc"
	workRoot         = "/work"
	tcpdumpPath      = "/usr/bin/tcpdump"
)

var (
	errTargetMissing     = errors.New("target pod processes disappeared")
	errTargetAmbiguous   = errors.New("target pod resolves to multiple network namespaces")
	errUnsupportedLayout = errors.New("target pod uses an unsupported cgroup or runtime layout")
	containerIDPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type options struct {
	podUID        string
	interfaceName string
	duration      int
	count         int
	snaplen       int
	filter        string
	output        string
}

type namespaceID struct {
	device uint64
	inode  uint64
}

type processSnapshot struct {
	pid           int
	startTime     string
	cgroup        string
	namespace     namespaceID
	runtimeFamily string
}

type targetSnapshot struct {
	processes []processSnapshot
	namespace namespaceID
}

type procScanner struct {
	root string
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: pod-netns-capture --pod-uid UID --output FILE [--interface IFACE] [--duration SECONDS] [--count PACKETS] [--snaplen BYTES] [--filter PCAP_FILTER]")
}

func parseOptions(args []string) (options, error) {
	opts := options{interfaceName: defaultInterface, duration: defaultDuration, count: defaultCount, snaplen: defaultSnaplen}
	set := make(map[string]bool)
	for len(args) > 0 {
		name := args[0]
		if name == "--help" || name == "-h" {
			return options{}, flag.ErrHelp
		}
		if !strings.HasPrefix(name, "--") {
			return options{}, fmt.Errorf("unexpected positional argument")
		}
		if set[name] {
			return options{}, fmt.Errorf("duplicate option %s", name)
		}
		if len(args) < 2 {
			return options{}, fmt.Errorf("missing value for %s", name)
		}
		value := args[1]
		set[name] = true
		args = args[2:]
		switch name {
		case "--pod-uid":
			opts.podUID = value
		case "--interface":
			opts.interfaceName = value
		case "--duration":
			parsed, err := boundedInteger(value, 1, maxDuration)
			if err != nil {
				return options{}, fmt.Errorf("invalid duration: %w", err)
			}
			opts.duration = parsed
		case "--count":
			parsed, err := boundedInteger(value, 1, maxCount)
			if err != nil {
				return options{}, fmt.Errorf("invalid count: %w", err)
			}
			opts.count = parsed
		case "--snaplen":
			parsed, err := boundedInteger(value, minSnaplen, maxSnaplen)
			if err != nil {
				return options{}, fmt.Errorf("invalid snaplen: %w", err)
			}
			opts.snaplen = parsed
		case "--filter":
			opts.filter = value
		case "--output":
			opts.output = value
		default:
			return options{}, fmt.Errorf("unknown option %s", name)
		}
	}
	if err := validatePodUID(opts.podUID); err != nil {
		return options{}, err
	}
	if err := validateInterface(opts.interfaceName); err != nil {
		return options{}, err
	}
	if err := validateFilter(opts.filter); err != nil {
		return options{}, err
	}
	if err := validateOutput(opts.output); err != nil {
		return options{}, err
	}
	return opts, nil
}

func boundedInteger(value string, minimum, maximum int) (int, error) {
	if value == "" || strings.HasPrefix(value, "+") || (len(value) > 1 && value[0] == '0') {
		return 0, fmt.Errorf("must be a canonical integer between %d and %d", minimum, maximum)
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("must be an integer between %d and %d", minimum, maximum)
	}
	return parsed, nil
}

func validatePodUID(uid string) error {
	if len(uid) != 36 {
		return fmt.Errorf("pod UID must be a canonical lowercase UUID")
	}
	for index, value := range []byte(uid) {
		switch index {
		case 8, 13, 18, 23:
			if value != '-' {
				return fmt.Errorf("pod UID must be a canonical lowercase UUID")
			}
		default:
			if !((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')) {
				return fmt.Errorf("pod UID must be a canonical lowercase UUID")
			}
		}
	}
	return nil
}

func validateInterface(name string) error {
	if name == "any" {
		return nil
	}
	if len(name) == 0 || len(name) > 15 {
		return fmt.Errorf("interface must be 'any' or 1 to 15 safe ASCII characters")
	}
	for index, value := range []byte(name) {
		if (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') {
			continue
		}
		if index > 0 && (value == '.' || value == '_' || value == '-') {
			continue
		}
		return fmt.Errorf("interface contains unsupported characters")
	}
	return nil
}

func validateFilter(expression string) error {
	if len(expression) > maxFilterBytes {
		return fmt.Errorf("capture filter exceeds %d bytes", maxFilterBytes)
	}
	for _, value := range []byte(expression) {
		if value < 0x20 || value > 0x7e {
			return fmt.Errorf("capture filter must contain printable ASCII only")
		}
	}
	return nil
}

func validateOutput(name string) error {
	if len(name) == 0 || len(name) > maxOutputBytes || name == "." || name == ".." {
		return fmt.Errorf("output must be a filename of 1 to %d bytes", maxOutputBytes)
	}
	for index, value := range []byte(name) {
		if (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') {
			continue
		}
		if index > 0 && (value == '.' || value == '_' || value == '-') {
			continue
		}
		return fmt.Errorf("output must be a safe filename below /work")
	}
	return nil
}

func uidRepresentations(uid string) []string {
	return []string{uid, strings.ReplaceAll(uid, "-", "_"), strings.ReplaceAll(uid, "-", `\x2d`)}
}

func (scanner procScanner) scanTarget(uid string) (targetSnapshot, error) {
	entries, err := os.ReadDir(scanner.root)
	if err != nil {
		return targetSnapshot{}, fmt.Errorf("read procfs: %w", err)
	}
	processes := make([]processSnapshot, 0)
	for _, entry := range entries {
		pid, ok := numericPID(entry.Name())
		if !ok || !entry.IsDir() {
			continue
		}
		process, matched, err := scanner.readProcess(pid, uid)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return targetSnapshot{}, err
		}
		if matched {
			processes = append(processes, process)
		}
	}
	if len(processes) == 0 {
		return targetSnapshot{}, errTargetMissing
	}
	sort.Slice(processes, func(left, right int) bool { return processes[left].pid < processes[right].pid })
	wantedNamespace := processes[0].namespace
	wantedRuntime := processes[0].runtimeFamily
	for _, process := range processes[1:] {
		if process.namespace != wantedNamespace {
			return targetSnapshot{}, errTargetAmbiguous
		}
		if process.runtimeFamily != wantedRuntime {
			return targetSnapshot{}, errUnsupportedLayout
		}
	}
	return targetSnapshot{processes: processes, namespace: wantedNamespace}, nil
}

func numericPID(name string) (int, bool) {
	if name == "" || (len(name) > 1 && name[0] == '0') {
		return 0, false
	}
	pid, err := strconv.Atoi(name)
	return pid, err == nil && pid > 0 && strconv.Itoa(pid) == name
}

func (scanner procScanner) readProcess(pid int, uid string) (processSnapshot, bool, error) {
	processDir := filepath.Join(scanner.root, strconv.Itoa(pid))
	firstStart, err := readStartTime(filepath.Join(processDir, "stat"))
	if err != nil {
		return processSnapshot{}, false, err
	}
	cgroupBytes, err := os.ReadFile(filepath.Join(processDir, "cgroup"))
	if err != nil {
		return processSnapshot{}, false, fmt.Errorf("read process cgroup: %w", err)
	}
	matched, runtimeFamily, err := matchTargetCgroup(cgroupBytes, uid)
	if err != nil {
		return processSnapshot{}, false, err
	}
	if !matched {
		return processSnapshot{}, false, nil
	}
	namespace, err := statNamespace(filepath.Join(processDir, "ns", "net"))
	if err != nil {
		return processSnapshot{}, false, fmt.Errorf("inspect target network namespace: %w", err)
	}
	secondStart, err := readStartTime(filepath.Join(processDir, "stat"))
	if err != nil {
		return processSnapshot{}, false, err
	}
	if firstStart != secondStart {
		return processSnapshot{}, false, fmt.Errorf("target process changed during discovery")
	}
	return processSnapshot{
		pid: pid, startTime: firstStart, cgroup: string(cgroupBytes), namespace: namespace, runtimeFamily: runtimeFamily,
	}, true, nil
}

func readStartTime(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read process identity: %w", err)
	}
	closing := bytes.LastIndexByte(contents, ')')
	if closing < 0 || closing+2 > len(contents) {
		return "", fmt.Errorf("process identity has an unsupported format")
	}
	fields := bytes.Fields(contents[closing+1:])
	// The tail begins at field 3 (state); starttime is field 22.
	if len(fields) <= 19 {
		return "", fmt.Errorf("process identity has an unsupported format")
	}
	if _, err := strconv.ParseUint(string(fields[19]), 10, 64); err != nil {
		return "", fmt.Errorf("process identity has an unsupported start time")
	}
	return string(fields[19]), nil
}

func statNamespace(path string) (namespaceID, error) {
	info, err := os.Stat(path)
	if err != nil {
		return namespaceID{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return namespaceID{}, fmt.Errorf("network namespace does not expose an inode")
	}
	return namespaceID{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func matchTargetCgroup(contents []byte, uid string) (bool, string, error) {
	representations := uidRepresentations(uid)
	matched := false
	runtimeFamily := ""
	lines := bytes.Split(contents, []byte{'\n'})
	for _, rawLine := range lines {
		if len(rawLine) == 0 {
			continue
		}
		line := string(rawLine)
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			if containsUIDRepresentation(strings.ToLower(line), representations) {
				return false, "", errUnsupportedLayout
			}
			continue
		}
		path := parts[2]
		lineMatched, family, suspicious := matchCgroupPath(path, representations)
		if suspicious {
			return false, "", errUnsupportedLayout
		}
		if !lineMatched {
			continue
		}
		if matched && family != runtimeFamily {
			return false, "", errUnsupportedLayout
		}
		matched = true
		runtimeFamily = family
	}
	return matched, runtimeFamily, nil
}

func containsUIDRepresentation(value string, representations []string) bool {
	for _, representation := range representations {
		if strings.Contains(value, representation) {
			return true
		}
	}
	return false
}

func matchCgroupPath(path string, representations []string) (bool, string, bool) {
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(components) == 1 && components[0] == "" {
		return false, "", false
	}
	// A private cgroup namespace renders a host-PID sibling as a bounded run of
	// leading ".." components (for example /../../../kubepods.slice/...). The
	// kernel supplies these components; they are not filesystem traversal. Peel
	// only a leading run, retain the exact Kubernetes root checks below, and
	// reject unexpectedly deep or embedded traversal.
	parentCount := 0
	for parentCount < len(components) && components[parentCount] == ".." {
		parentCount++
	}
	if parentCount > 16 || parentCount == len(components) {
		return false, "", containsUIDRepresentation(strings.ToLower(path), representations)
	}
	components = components[parentCount:]
	for _, component := range components {
		if component == ".." || component == "." || component == "" {
			return false, "", containsUIDRepresentation(strings.ToLower(path), representations)
		}
	}
	for representationIndex, representation := range representations {
		classicMarker := "pod" + representation
		for index, component := range components {
			if podComponent, runtime, ok := inlineSystemdRuntime(component, classicMarker); ok {
				layout := append([]string(nil), components[:index]...)
				layout = append(layout, podComponent, runtime)
				if representationIndex == 0 || !validSystemdLayout(layout, index, classicMarker, parentCount) {
					return false, "", true
				}
				family, ok := runtimeComponent(runtime)
				return ok, family, !ok
			}
			if component == classicMarker {
				if !validClassicLayout(components, index, parentCount) {
					return false, "", true
				}
				family, ok := runtimeComponent(components[index+1])
				return ok, family, !ok
			}
			if strings.HasSuffix(component, "-"+classicMarker+".slice") {
				if representationIndex == 0 || !validSystemdLayout(components, index, classicMarker, parentCount) {
					return false, "", true
				}
				family, ok := runtimeComponent(components[index+1])
				return ok, family, !ok
			}
		}
	}
	if containsUIDRepresentation(strings.ToLower(path), representations) {
		return false, "", true
	}
	return false, "", false
}

func inlineSystemdRuntime(component, marker string) (string, string, bool) {
	suffix := "-" + marker + ".slice:"
	index := strings.Index(component, suffix)
	if index < 0 {
		return "", "", false
	}
	podComponent := component[:index+len(suffix)-1]
	runtimeParts := strings.Split(component[index+len(suffix):], ":")
	if len(runtimeParts) != 2 {
		return "", "", false
	}
	return podComponent, runtimeParts[0] + "-" + runtimeParts[1], true
}

func validClassicLayout(components []string, podIndex, parentCount int) bool {
	if podIndex+2 != len(components) {
		return false
	}
	if components[0] == "kubepods" {
		if podIndex < 1 {
			return false
		}
		if podIndex == 1 {
			return true
		}
		return podIndex == 2 && (components[1] == "burstable" || components[1] == "besteffort")
	}
	// From a container-rooted private cgroup namespace, a target in the same
	// QoS class is ../../podUID/CONTAINER. Crossing a QoS boundary retains the
	// target QoS component after two or three leading parents.
	if parentCount < 2 || parentCount > 3 {
		return false
	}
	return podIndex == 0 || (podIndex == 1 && (components[0] == "burstable" || components[0] == "besteffort"))
}

func validSystemdLayout(components []string, podIndex int, marker string, parentCount int) bool {
	if podIndex+2 != len(components) {
		return false
	}
	if components[0] != "kubepods.slice" {
		if parentCount < 2 || parentCount > 3 {
			return false
		}
		if podIndex == 0 {
			return components[0] == "kubepods-"+marker+".slice" ||
				components[0] == "kubepods-burstable-"+marker+".slice" ||
				components[0] == "kubepods-besteffort-"+marker+".slice"
		}
		if podIndex != 1 {
			return false
		}
		qos := components[0]
		if qos != "kubepods-burstable.slice" && qos != "kubepods-besteffort.slice" {
			return false
		}
		return components[1] == strings.TrimSuffix(qos, ".slice")+"-"+marker+".slice"
	}
	wantedPod := ""
	switch podIndex {
	case 1:
		wantedPod = "kubepods-" + marker + ".slice"
	case 2:
		qos := components[1]
		if qos != "kubepods-burstable.slice" && qos != "kubepods-besteffort.slice" {
			return false
		}
		wantedPod = strings.TrimSuffix(qos, ".slice") + "-" + marker + ".slice"
	default:
		return false
	}
	return components[podIndex] == wantedPod
}

func runtimeComponent(component string) (string, bool) {
	if containerIDPattern.MatchString(component) {
		return "cgroupfs-cri", true
	}
	for _, family := range []string{"cri-containerd", "crio", "docker"} {
		prefix := family + "-"
		if strings.HasPrefix(component, prefix) && strings.HasSuffix(component, ".scope") {
			containerID := strings.TrimSuffix(strings.TrimPrefix(component, prefix), ".scope")
			if containerIDPattern.MatchString(containerID) {
				return family, true
			}
		}
	}
	return "", false
}

func (scanner procScanner) revalidate(anchor processSnapshot, uid string, openedNamespace namespaceID) error {
	current, matched, err := scanner.readProcess(anchor.pid, uid)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errTargetMissing
		}
		return err
	}
	if !matched || current.startTime != anchor.startTime || current.cgroup != anchor.cgroup || current.namespace != openedNamespace {
		return fmt.Errorf("target process identity changed before namespace entry")
	}
	finalTarget, err := scanner.scanTarget(uid)
	if err != nil {
		return err
	}
	if finalTarget.namespace != openedNamespace {
		return errTargetAmbiguous
	}
	current, matched, err = scanner.readProcess(anchor.pid, uid)
	if err != nil || !matched {
		return errTargetMissing
	}
	if current.startTime != anchor.startTime || current.cgroup != anchor.cgroup || current.namespace != openedNamespace {
		return fmt.Errorf("target process identity changed during final validation")
	}
	return nil
}

func pcapPacketCount(reader io.Reader, packetLimit, snaplen int) (int, error) {
	header := make([]byte, 24)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, fmt.Errorf("capture does not contain a complete pcap header")
	}
	var order binary.ByteOrder
	switch [4]byte(header[:4]) {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}, [4]byte{0x4d, 0x3c, 0xb2, 0xa1}:
		order = binary.LittleEndian
	case [4]byte{0xa1, 0xb2, 0xc3, 0xd4}, [4]byte{0xa1, 0xb2, 0x3c, 0x4d}:
		order = binary.BigEndian
	default:
		return 0, fmt.Errorf("capture is not classic pcap")
	}
	if int(order.Uint32(header[16:20])) != snaplen {
		return 0, fmt.Errorf("capture snaplen differs from the requested bound")
	}
	count := 0
	recordHeader := make([]byte, 16)
	for {
		_, err := io.ReadFull(reader, recordHeader)
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return 0, fmt.Errorf("capture contains a truncated record header")
		}
		includedLength := int(order.Uint32(recordHeader[8:12]))
		if includedLength < 0 || includedLength > snaplen {
			return 0, fmt.Errorf("capture record exceeds the snaplen bound")
		}
		if _, err := io.CopyN(io.Discard, reader, int64(includedLength)); err != nil {
			return 0, fmt.Errorf("capture contains a truncated packet record")
		}
		count++
		if count > packetLimit {
			return 0, fmt.Errorf("capture exceeds the packet-count bound")
		}
	}
}

func captureSizeBound(count, snaplen int) int64 {
	return int64(24 + count*(16+snaplen))
}

func hashAndInspectCapture(file *os.File, opts options) (int, int64, string, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, 0, "", fmt.Errorf("stat capture: %w", err)
	}
	if info.Size() > captureSizeBound(opts.count, opts.snaplen) {
		return 0, 0, "", fmt.Errorf("capture exceeds the output-size bound")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, 0, "", fmt.Errorf("rewind capture: %w", err)
	}
	packetCount, err := pcapPacketCount(io.LimitReader(file, captureSizeBound(opts.count, opts.snaplen)+1), opts.count, opts.snaplen)
	if err != nil {
		return 0, 0, "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, 0, "", fmt.Errorf("rewind capture for hashing: %w", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(file, info.Size())); err != nil {
		return 0, 0, "", fmt.Errorf("hash capture: %w", err)
	}
	finalInfo, err := file.Stat()
	if err != nil || finalInfo.Size() != info.Size() {
		return 0, 0, "", fmt.Errorf("capture changed during validation")
	}
	return packetCount, info.Size(), fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

func stableError(err error) string {
	switch {
	case errors.Is(err, errTargetMissing):
		return "target pod is not present in the visible host PID namespace"
	case errors.Is(err, errTargetAmbiguous):
		return "target pod network namespace is ambiguous"
	case errors.Is(err, errUnsupportedLayout):
		return "target pod cgroup/runtime layout is unsupported"
	default:
		return err.Error()
	}
}

func outputSummary(writer io.Writer, opts options, packets int, size int64, hash string) error {
	_, err := fmt.Fprintf(writer, "capture_status complete\npod_uid %s\ninterface %s\nduration_seconds %d\npacket_limit %d\nsnaplen_bytes %d\npacket_count %d\nbytes %d\nsha256 %s\noutput %s\n",
		opts.podUID, opts.interfaceName, opts.duration, opts.count, opts.snaplen, packets, size, hash, opts.output)
	return err
}

func waitBound(duration int) time.Duration {
	return time.Duration(duration) * time.Second
}
