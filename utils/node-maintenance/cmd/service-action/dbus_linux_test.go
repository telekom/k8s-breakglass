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
	calls := make(chan fakeCall, 64)
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
				for range r.signature {
					value, _ := d.string()
					args = append(args, value)
				}
				calls <- fakeCall{member: member, args: args}
				serial := binary.LittleEndian.Uint32(r.body[8:12])
				switch member {
				case "Ping":
					_, _ = conn.Write(fakeReply(serial, "", nil))
				case "LoadUnit", "RestartUnit":
					_, _ = conn.Write(fakeReply(serial, "o", "/org/freedesktop/systemd1/unit/"+strings.ReplaceAll(args[0], ".", "_2e")))
				case "Get":
					unit := strings.TrimPrefix(fields[fieldPath], "/org/freedesktop/systemd1/unit/")
					unit = strings.ReplaceAll(unit, "_2e", ".")
					value, ok := states[unit][args[1]]
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
