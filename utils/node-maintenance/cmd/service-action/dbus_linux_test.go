// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeCall struct {
	member string
	args   []string
}

// fakeSystemd serves the private-socket protocol subset: EXTERNAL auth,
// NEGOTIATE_UNIX_FD, a dropped first call (as sd-bus does before the switch
// to messages), Ping, LoadUnit, Properties.Get and RestartUnit.
func fakeSystemd(t *testing.T, states map[string]map[string]any) (string, chan fakeCall) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "private")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	// Large enough that a test never blocks the fake before it drains calls.
	calls := make(chan fakeCall, 4096)
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go serveFake(conn, states, calls)
		}
	}()
	return socket, calls
}

func serveFake(conn *net.UnixConn, states map[string]map[string]any, calls chan fakeCall) {
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1) })
	// The credentials byte must carry SCM_CREDENTIALS.
	buf, oob := make([]byte, 1), make([]byte, 128)
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil || buf[0] != 0 || oobn == 0 {
		return
	}
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		switch {
		case strings.HasPrefix(line, "AUTH EXTERNAL "):
			_, _ = conn.Write([]byte("OK 0123456789abcdef0123456789abcdef\r\n"))
		case strings.HasPrefix(line, "NEGOTIATE_UNIX_FD"):
			_, _ = conn.Write([]byte("AGREE_UNIX_FD\r\n"))
		case strings.HasPrefix(line, "BEGIN"):
			dropped := false
			client := &dbusConn{conn: conn, reader: reader}
			for {
				r, err := client.readMessage()
				if err != nil {
					return
				}
				d := &decoder{data: r.body, pos: r.bodyOffset}
				fields := headerFields(r.body)
				member := fields[fieldMember]
				if !dropped {
					dropped = true
					continue
				}
				var args []string
				if member == "StartTransientUnit" {
					args = decodeTransient(d)
				} else {
					for range r.signature {
						value, _ := d.string()
						args = append(args, value)
					}
				}
				calls <- fakeCall{member: member, args: args}
				serial := binary.LittleEndian.Uint32(r.body[8:12])
				switch member {
				case "Ping":
					_, _ = conn.Write(fakeReply(serial, "", nil))
				case "LoadUnit", "RestartUnit":
					_, _ = conn.Write(fakeReply(serial, "o", "/org/freedesktop/systemd1/unit/"+strings.ReplaceAll(args[0], ".", "_2e")))
				case "StartTransientUnit":
					// A command whose argv names "bad0" fails like a nonzero exit; "slow0"
					// runs for 6 reads (1.5 s), "hang0" never finishes.
					state := map[string]any{"LoadState": "loaded", "ActiveState": "active", "Result": "success", "ExecMainStatus": int32(0)}
					switch {
					case strings.Contains(args[2], "bad0"):
						state = map[string]any{"LoadState": "loaded", "ActiveState": "failed", "Result": "exit-code", "ExecMainStatus": int32(1)}
					case strings.Contains(args[2], "slow0"):
						state["_activating"] = 6
					case strings.Contains(args[2], "hang0"):
						state["_activating"] = 1 << 30
					}
					states[args[0]] = state
					_, _ = conn.Write(fakeReply(serial, "o", "/org/freedesktop/systemd1/job/7"))
				case "StopUnit", "ResetFailedUnit":
					delete(states, args[0])
					_, _ = conn.Write(fakeReply(serial, "o", "/org/freedesktop/systemd1/job/8"))
				case "Get":
					unit := strings.TrimPrefix(fields[fieldPath], "/org/freedesktop/systemd1/unit/")
					unit = strings.ReplaceAll(unit, "_2e", ".")
					value, ok := states[unit][args[1]]
					// "_activating" makes the next N ActiveState reads report a running command.
					if n, _ := states[unit]["_activating"].(int); n > 0 && args[1] == "ActiveState" {
						states[unit]["_activating"] = n - 1
						value = "activating"
					}
					if !ok {
						value = map[string]any{"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "ActiveEnterTimestampMonotonic": uint64(0), "NRestarts": uint32(0)}[args[1]]
					}
					_, _ = conn.Write(fakeReply(serial, "v", value))
				}
			}
		}
	}
}

// headerFields decodes string-valued header fields of a received message.
func headerFields(data []byte) map[byte]string {
	fieldsLen := int(binary.LittleEndian.Uint32(data[12:16]))
	d := &decoder{data: data[:16+fieldsLen], pos: 16}
	out := map[byte]string{}
	for d.pos < 16+fieldsLen {
		if d.align(8) != nil || d.pos >= 16+fieldsLen {
			break
		}
		code, _ := d.byte()
		sig, _ := d.signature()
		value, err := d.value(sig)
		if err != nil {
			break
		}
		if text, ok := value.(string); ok {
			out[code] = text
		}
	}
	return out
}

// fakeReply encodes a METHOD_RETURN with an "o", a "v" (s, u or t) or no body.
func fakeReply(replySerial uint32, sig string, value any) []byte {
	body := &encoder{}
	switch sig {
	case "o":
		body.string(value.(string))
	case "v":
		switch v := value.(type) {
		case string:
			body.signature("s")
			body.string(v)
		case uint32:
			body.signature("u")
			body.uint32(v)
		case int32:
			body.signature("i")
			body.uint32(uint32(v))
		case uint64:
			body.signature("t")
			body.align(8)
			bytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(bytes, v)
			body.buf.Write(bytes)
		}
	}
	head := &encoder{}
	head.byte('l')
	head.byte(msgMethodReturn)
	head.byte(1)
	head.byte(1)
	head.uint32(uint32(body.buf.Len()))
	head.uint32(1000 + replySerial)
	head.uint32(0)
	lengthOffset := head.buf.Len() - 4
	start := head.buf.Len()
	head.align(8)
	head.byte(fieldReplySerial)
	head.signature("u")
	head.uint32(replySerial)
	if sig != "" {
		head.align(8)
		head.byte(fieldSignature)
		head.signature("g")
		head.signature(sig)
	}
	binary.LittleEndian.PutUint32(head.buf.Bytes()[lengthOffset:], uint32(head.buf.Len()-start))
	head.align(8)
	return append(head.buf.Bytes(), body.buf.Bytes()...)
}

func TestParseRequestAllowlist(t *testing.T) {
	for _, args := range [][]string{{"restart", "containerd.service"}, {"probe", "cra.service"}, {"restart", "kubelet.service"}} {
		if _, err := parseRequest(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"stop", "containerd.service"}, {"restart", "sshd.service"}, {"restart"}, {"restart", "cra.service", "x"},
		{"restart", "../cra.service"}, {"restart", "containerd.service\n"}} {
		if _, err := parseRequest(args); err == nil {
			t.Fatalf("%v was accepted", args)
		}
	}
}

func TestProbeAndRestartOverPrivateSocket(t *testing.T) {
	states := map[string]map[string]any{"containerd.service": {
		"LoadState": "loaded", "ActiveState": "active", "SubState": "running",
		"ActiveEnterTimestampMonotonic": uint64(66551225451), "NRestarts": uint32(2),
	}}
	socket, calls := fakeSystemd(t, states)
	stdout := os.Stdout
	read, write, _ := os.Pipe()
	os.Stdout = write
	err := run(request{command: "probe", unit: "containerd.service"}, socket)
	_ = write.Close()
	os.Stdout = stdout
	if err != nil {
		t.Fatal(err)
	}
	output := make([]byte, 512)
	n, _ := read.Read(output)
	want := "unit=containerd.service load_state=loaded active_state=active sub_state=running n_restarts=2 active_enter_monotonic_us=66551225451\n"
	if string(output[:n]) != want {
		t.Fatalf("probe printed %q, want %q", output[:n], want)
	}
	if err := run(request{command: "restart", unit: "containerd.service"}, socket); err != nil {
		t.Fatal(err)
	}
	restarted := false
	timeout := time.After(5 * time.Second)
	for !restarted {
		select {
		case call := <-calls:
			if call.member == "RestartUnit" {
				if strings.Join(call.args, ",") != "containerd.service,replace" {
					t.Fatalf("RestartUnit args %v", call.args)
				}
				restarted = true
			}
		case <-timeout:
			t.Fatal("RestartUnit was never sent")
		}
	}
	// A unit that is not loaded on the node is never restarted.
	if err := run(request{command: "restart", unit: "cra.service"}, socket); err == nil || !strings.Contains(err.Error(), "not-found") {
		t.Fatalf("restart of a missing unit: %v", err)
	}
}

func TestReadMessageRejectsMalformedReplies(t *testing.T) {
	valid := fakeReply(7, "o", "/org/freedesktop/systemd1/unit/x")
	read := func(data []byte) error {
		client, server := net.Pipe()
		defer client.Close()
		go func() { _, _ = server.Write(data); _ = server.Close() }()
		c := &dbusConn{reader: bufio.NewReader(client)}
		_, err := c.readMessage()
		return err
	}
	if err := read(valid); err != nil {
		t.Fatalf("valid reply: %v", err)
	}
	bigEndian := append([]byte{}, valid...)
	bigEndian[0] = 'B'
	oldVersion := append([]byte{}, valid...)
	oldVersion[3] = 2
	oversized := append([]byte{}, valid...)
	binary.LittleEndian.PutUint32(oversized[4:8], maxMessageBytes+1)
	for name, data := range map[string][]byte{
		"big endian": bigEndian, "protocol version": oldVersion, "oversized body": oversized, "truncated": valid[:len(valid)-3],
	} {
		if err := read(data); err == nil {
			t.Fatalf("%s reply was accepted", name)
		}
	}
	d := &decoder{data: []byte{1, 'x', 0}}
	if _, err := d.value("a{sv}"); err == nil {
		t.Fatal("an unsupported type was decoded")
	}
}

// decodeTransient returns [unit, mode, "path|argv..."] and checks the fixed
// property set of a StartTransientUnit body.
func decodeTransient(d *decoder) []string {
	unit, _ := d.string()
	mode, _ := d.string()
	propsLen, _ := d.uint32()
	_ = d.align(8)
	end := d.pos + int(propsLen)
	exec := ""
	names := []string{}
	for d.pos < end {
		_ = d.align(8)
		name, _ := d.string()
		sig, _ := d.signature()
		names = append(names, name)
		switch sig {
		case "s":
			_, _ = d.string()
		case "b":
			_, _ = d.uint32()
		case "t":
			v, _ := d.uint64()
			if name == "TimeoutStopUSec" && v != 15_000_000 || name == "TimeoutStartUSec" && v <= 5_000_000 {
				return []string{unit, mode, "unexpected " + name}
			}
		case "a(sasb)":
			_, _ = d.uint32()
			_ = d.align(8)
			path, _ := d.string()
			argvLen, _ := d.uint32()
			argvEnd := d.pos + int(argvLen)
			argv := []string{path}
			for d.pos < argvEnd {
				arg, _ := d.string()
				argv = append(argv, arg)
			}
			_, _ = d.uint32()
			exec = strings.Join(argv, "|")
		default:
			return []string{unit, mode, "unexpected property type " + sig}
		}
	}
	auxLen, _ := d.uint32()
	if strings.Join(names, ",") != "Description,Type,RemainAfterExit,TimeoutStopUSec,TimeoutStartUSec,ExecStart" || auxLen != 0 {
		return []string{unit, mode, "unexpected properties " + strings.Join(names, ",")}
	}
	return []string{unit, mode, exec}
}

func TestParseRequestNetplan(t *testing.T) {
	for _, args := range [][]string{{"netplan-sriov-apply"}, {"netplan-rebind", "enp1s0"}, {"netplan-rebind", "ens1f0np0"}} {
		if _, err := parseRequest(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"netplan-sriov-apply", "x"}, {"netplan-rebind"}, {"netplan-rebind", "a", "b"},
		{"netplan-rebind", "../x"}, {"netplan-rebind", "."}, {"netplan-rebind", "-h"}, {"netplan-rebind", "toolonginterface0"}, {"netplan-rebind", "-x y"},
		{"netplan", "apply"}, {"netplan-apply"}} {
		if _, err := parseRequest(args); err == nil {
			t.Fatalf("%v was accepted", args)
		}
	}
}

func TestNetplanCommandsRunAsTransientUnits(t *testing.T) {
	socket, calls := fakeSystemd(t, map[string]map[string]any{})
	if err := run(request{command: "netplan-sriov-apply"}, socket); err != nil {
		t.Fatal(err)
	}
	if err := run(request{command: "netplan-rebind", pf: "enp1s0"}, socket); err != nil {
		t.Fatal(err)
	}
	err := run(request{command: "netplan-rebind", pf: "bad0"}, socket)
	if err == nil || !strings.Contains(err.Error(), "exec_main_status=1") {
		t.Fatalf("failed command: %v", err)
	}
	var started []string
	timeout := time.After(5 * time.Second)
	for len(started) < 3 {
		select {
		case call := <-calls:
			if call.member == "StartTransientUnit" {
				started = append(started, strings.Join(call.args, " "))
			}
		case <-timeout:
			t.Fatalf("started only %v", started)
		}
	}
	want := []string{
		"breakglass-netplan-sriov-apply.service fail /usr/sbin/netplan|/usr/sbin/netplan|apply|--sriov-only",
		"breakglass-netplan-rebind.service fail /usr/sbin/netplan|/usr/sbin/netplan|rebind|enp1s0",
		"breakglass-netplan-rebind.service fail /usr/sbin/netplan|/usr/sbin/netplan|rebind|bad0",
	}
	if strings.Join(started, "\n") != strings.Join(want, "\n") {
		t.Fatalf("StartTransientUnit calls:\n%s\nwant:\n%s", strings.Join(started, "\n"), strings.Join(want, "\n"))
	}
}

func TestTransientRunPollsBeyondOneCallDeadlineAndClearsLeftovers(t *testing.T) {
	saved := callTimeout
	callTimeout = 500 * time.Millisecond
	t.Cleanup(func() { callTimeout = saved })
	// A leftover unit of an interrupted run is stopped before the new run.
	socket, calls := fakeSystemd(t, map[string]map[string]any{
		"breakglass-netplan-rebind.service": {"LoadState": "loaded", "ActiveState": "activating"},
	})
	c, err := dialSystemd(socket, os.Getuid(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	// The run takes 1.5 s, three times the per-call deadline.
	if err := runTransient(c, "breakglass-netplan-rebind.service", []string{netplanBinary, "rebind", "slow0"}, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	var members []string
	timeout := time.After(5 * time.Second)
	for len(members) == 0 || members[len(members)-1] != "StopUnit" || !contains(members, "StartTransientUnit") {
		select {
		case call := <-calls:
			if call.member == "StopUnit" || call.member == "StartTransientUnit" {
				members = append(members, call.member)
			}
		case <-timeout:
			t.Fatalf("calls %v", members)
		}
	}
	if members[0] != "StopUnit" || members[1] != "StartTransientUnit" {
		t.Fatalf("the leftover unit was not stopped first: %v", members)
	}
}

func TestTransientRunTimeoutStopsTheUnit(t *testing.T) {
	socket, calls := fakeSystemd(t, map[string]map[string]any{})
	c, err := dialSystemd(socket, os.Getuid(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	err = runTransient(c, "breakglass-netplan-rebind.service", []string{netplanBinary, "rebind", "hang0"}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "did not finish within 1s") {
		t.Fatalf("hanging command: %v", err)
	}
	timeout := time.After(5 * time.Second)
	for {
		select {
		case call := <-calls:
			if call.member == "StopUnit" {
				return
			}
		case <-timeout:
			t.Fatal("the timed-out unit was never stopped")
		}
	}
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
