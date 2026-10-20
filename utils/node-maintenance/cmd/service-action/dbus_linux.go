// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// A deliberately tiny peer-to-peer D-Bus client for systemd's private socket
// (/run/systemd/private). It marshals only the types the fixed calls need
// (y, u, t, s, o, g, v and the header struct array) and never exposes a
// generic method call to its caller.

const (
	msgMethodCall   = 1
	msgMethodReturn = 2
	msgError        = 3

	fieldPath        = 1
	fieldInterface   = 2
	fieldMember      = 3
	fieldErrorName   = 4
	fieldReplySerial = 5
	fieldDestination = 6
	fieldSignature   = 8

	maxMessageBytes = 1 << 20
)

type dbusConn struct {
	conn   *net.UnixConn
	reader *bufio.Reader
	serial uint32
}

func dialSystemd(path string, uid int, timeout time.Duration) (*dbusConn, error) {
	raw, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", path, err)
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, fmt.Errorf("connect %s: not a unix socket", path)
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	c := &dbusConn{conn: conn, reader: bufio.NewReader(conn)}
	if err := c.authenticate(uid); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := c.ready(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *dbusConn) close() { _ = c.conn.Close() }

// ready pings until systemd answers. sd-bus drops a call that arrives before
// it has switched the connection from authentication to messages, so the
// first real call is sent only after a Peer.Ping round trip.
func (c *dbusConn) ready(deadline time.Time) error {
	first := c.serial + 1
	for time.Now().Before(deadline) {
		if err := c.send(managerPath, "org.freedesktop.DBus.Peer", "Ping", ""); err != nil {
			return err
		}
		// Wait briefly for the first reply byte only, so a timeout never
		// leaves a partially read message in the buffer.
		_ = c.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		if _, err := c.reader.Peek(1); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("read D-Bus Peer.Ping reply: %w", err)
		}
		if err := c.conn.SetDeadline(deadline); err != nil {
			return err
		}
		for {
			r, err := c.readMessage()
			if err != nil {
				return err
			}
			if (r.kind == msgMethodReturn || r.kind == msgError) && r.replySerial >= first && r.replySerial <= c.serial {
				if r.kind == msgError {
					return fmt.Errorf("D-Bus Peer.Ping failed: %s", r.errorName)
				}
				return nil
			}
		}
	}
	return errors.New("systemd did not answer D-Bus Peer.Ping before the deadline")
}

// authLine reads one bounded authentication line.
func (c *dbusConn) authLine() (string, error) {
	var line []byte
	for len(line) < 256 {
		b, err := c.reader.ReadByte()
		if err != nil {
			return "", err
		}
		line = append(line, b)
		if b == '\n' {
			return string(line), nil
		}
	}
	return "", errors.New("D-Bus authentication line exceeds 256 bytes")
}

// credentials returns an SCM_CREDENTIALS control message. systemd negotiates
// peer credentials on its private bus and does not dispatch a method call that
// arrives without them.
func credentials() []byte {
	pid := os.Getpid()
	if pid < 0 || pid > math.MaxInt32 {
		panic("process ID outside the kernel pid_t range")
	}
	return syscall.UnixCredentials(&syscall.Ucred{Pid: int32(pid), Uid: u32(os.Getuid()), Gid: u32(os.Getgid())})
}

// u32 converts a length or ID that the protocol carries as uint32. Every
// caller passes a value bounded by the argument length or a kernel ID.
func u32(n int) uint32 {
	if n < 0 || uint64(n) > math.MaxUint32 {
		panic("value outside the D-Bus uint32 range")
	}
	return uint32(n)
}

func (c *dbusConn) authenticate(uid int) error {
	if _, _, err := c.conn.WriteMsgUnix([]byte{0}, credentials(), nil); err != nil {
		return fmt.Errorf("send D-Bus credentials byte: %w", err)
	}
	auth := "AUTH EXTERNAL " + hex.EncodeToString([]byte(strconv.Itoa(uid))) + "\r\n"
	if _, err := io.WriteString(c.conn, auth); err != nil {
		return fmt.Errorf("send D-Bus auth: %w", err)
	}
	line, err := c.authLine()
	if err != nil {
		return fmt.Errorf("read D-Bus auth reply: %w", err)
	}
	if !strings.HasPrefix(line, "OK ") {
		return fmt.Errorf("D-Bus EXTERNAL authentication rejected: %q", strings.TrimSpace(line))
	}
	// sd-bus servers only attach peer credentials once fd passing was
	// negotiated; without it systemd never dispatches the call.
	if _, err := io.WriteString(c.conn, "NEGOTIATE_UNIX_FD\r\n"); err != nil {
		return fmt.Errorf("send D-Bus NEGOTIATE_UNIX_FD: %w", err)
	}
	if line, err = c.authLine(); err != nil {
		return fmt.Errorf("read D-Bus NEGOTIATE_UNIX_FD reply: %w", err)
	}
	if !strings.HasPrefix(line, "AGREE_UNIX_FD") {
		return fmt.Errorf("D-Bus NEGOTIATE_UNIX_FD not agreed: %q", strings.TrimSpace(line))
	}
	if _, err := io.WriteString(c.conn, "BEGIN\r\n"); err != nil {
		return fmt.Errorf("send D-Bus BEGIN: %w", err)
	}
	return nil
}

// encoder writes little-endian D-Bus wire data with alignment relative to the
// start of the message.
type encoder struct{ buf bytes.Buffer }

func (e *encoder) align(n int) {
	for e.buf.Len()%n != 0 {
		e.buf.WriteByte(0)
	}
}
func (e *encoder) byte(v byte) { e.buf.WriteByte(v) }
func (e *encoder) uint32(v uint32) {
	e.align(4)
	_ = binary.Write(&e.buf, binary.LittleEndian, v)
}
func (e *encoder) uint64(v uint64) {
	e.align(8)
	_ = binary.Write(&e.buf, binary.LittleEndian, v)
}
func (e *encoder) string(v string) {
	e.uint32(u32(len(v)))
	e.buf.WriteString(v)
	e.buf.WriteByte(0)
}
func (e *encoder) signature(v string) {
	n := len(v)
	if n > math.MaxUint8 {
		panic("D-Bus signature longer than 255 bytes")
	}
	e.byte(byte(n))
	e.buf.WriteString(v)
	e.buf.WriteByte(0)
}

type headerField struct {
	code  byte
	sig   string // "s", "o", "g" or "u"
	value any
}

// beginArray writes an array length placeholder and the padding to the
// element alignment; endArray patches the length (bytes after that padding).
func (e *encoder) beginArray(elementAlign int) (lengthOffset, start int) {
	e.uint32(0)
	lengthOffset = e.buf.Len() - 4
	e.align(elementAlign)
	return lengthOffset, e.buf.Len()
}
func (e *encoder) endArray(lengthOffset, start int) {
	binary.LittleEndian.PutUint32(e.buf.Bytes()[lengthOffset:], u32(e.buf.Len()-start))
}

func stringsBody(args []string) *encoder {
	body := &encoder{}
	for _, s := range args {
		body.string(s)
	}
	return body
}

func encodeMessage(serial uint32, fields []headerField, bodySig string, body *encoder) []byte {
	if bodySig != "" {
		fields = append(fields, headerField{fieldSignature, "g", bodySig})
	}
	head := &encoder{}
	head.byte('l')
	head.byte(msgMethodCall)
	head.byte(0)
	head.byte(1)
	head.uint32(u32(body.buf.Len()))
	head.uint32(serial)
	// Array of struct(byte, variant): length placeholder, filled below.
	head.uint32(0)
	lengthOffset := head.buf.Len() - 4
	head.align(8)
	start := head.buf.Len()
	for _, f := range fields {
		head.align(8)
		head.byte(f.code)
		head.signature(f.sig)
		switch f.sig {
		case "s", "o":
			head.string(f.value.(string))
		case "g":
			head.signature(f.value.(string))
		case "u":
			head.uint32(f.value.(uint32))
		}
	}
	binary.LittleEndian.PutUint32(head.buf.Bytes()[lengthOffset:], u32(head.buf.Len()-start))
	head.align(8)
	return append(head.buf.Bytes(), body.buf.Bytes()...)
}

// decoder reads little-endian D-Bus wire data; offsets are relative to the
// message start so alignment matches the sender.
type decoder struct {
	data []byte
	pos  int
}

func (d *decoder) align(n int) error {
	for d.pos%n != 0 {
		d.pos++
	}
	if d.pos > len(d.data) {
		return errors.New("short D-Bus message")
	}
	return nil
}
func (d *decoder) byte() (byte, error) {
	if d.pos >= len(d.data) {
		return 0, errors.New("short D-Bus message")
	}
	v := d.data[d.pos]
	d.pos++
	return v, nil
}
func (d *decoder) uint32() (uint32, error) {
	if err := d.align(4); err != nil {
		return 0, err
	}
	if d.pos+4 > len(d.data) {
		return 0, errors.New("short D-Bus message")
	}
	v := binary.LittleEndian.Uint32(d.data[d.pos:])
	d.pos += 4
	return v, nil
}
func (d *decoder) int32() (int32, error) {
	if err := d.align(4); err != nil {
		return 0, err
	}
	var v int32
	if d.pos+4 > len(d.data) {
		return 0, errors.New("short D-Bus message")
	}
	if err := binary.Read(bytes.NewReader(d.data[d.pos:d.pos+4]), binary.LittleEndian, &v); err != nil {
		return 0, err
	}
	d.pos += 4
	return v, nil
}
func (d *decoder) uint64() (uint64, error) {
	if err := d.align(8); err != nil {
		return 0, err
	}
	if d.pos+8 > len(d.data) {
		return 0, errors.New("short D-Bus message")
	}
	v := binary.LittleEndian.Uint64(d.data[d.pos:])
	d.pos += 8
	return v, nil
}
func (d *decoder) string() (string, error) {
	n, err := d.uint32()
	if err != nil {
		return "", err
	}
	if n > maxMessageBytes || d.pos+int(n)+1 > len(d.data) {
		return "", errors.New("invalid D-Bus string length")
	}
	v := string(d.data[d.pos : d.pos+int(n)])
	d.pos += int(n) + 1
	return v, nil
}
func (d *decoder) signature() (string, error) {
	n, err := d.byte()
	if err != nil {
		return "", err
	}
	if d.pos+int(n)+1 > len(d.data) {
		return "", errors.New("invalid D-Bus signature length")
	}
	v := string(d.data[d.pos : d.pos+int(n)])
	d.pos += int(n) + 1
	return v, nil
}

// value reads one value of a basic type or a variant of a basic type.
func (d *decoder) value(sig string) (any, error) {
	switch sig {
	case "y":
		return d.byte()
	case "u":
		return d.uint32()
	case "i":
		return d.int32()
	case "t":
		return d.uint64()
	case "s", "o":
		return d.string()
	case "g":
		return d.signature()
	case "v":
		inner, err := d.signature()
		if err != nil {
			return nil, err
		}
		return d.value(inner)
	}
	return nil, fmt.Errorf("unsupported D-Bus type %q", sig)
}

type reply struct {
	kind        byte
	replySerial uint32
	errorName   string
	signature   string
	body        []byte
	bodyOffset  int
}

func (c *dbusConn) readMessage() (*reply, error) {
	fixed := make([]byte, 16)
	if _, err := io.ReadFull(c.reader, fixed); err != nil {
		return nil, fmt.Errorf("read D-Bus message: %w", err)
	}
	if fixed[0] != 'l' || fixed[3] != 1 {
		return nil, errors.New("only little-endian D-Bus protocol version 1 replies are supported")
	}
	bodyLen := binary.LittleEndian.Uint32(fixed[4:8])
	fieldsLen := binary.LittleEndian.Uint32(fixed[12:16])
	headerLen := 16 + int(fieldsLen)
	padded := (headerLen + 7) &^ 7
	if fieldsLen > maxMessageBytes || bodyLen > maxMessageBytes {
		return nil, errors.New("D-Bus message exceeds the size limit")
	}
	rest := make([]byte, padded-16+int(bodyLen))
	if _, err := io.ReadFull(c.reader, rest); err != nil {
		return nil, fmt.Errorf("read D-Bus message: %w", err)
	}
	data := append(fixed, rest...)
	r := &reply{kind: fixed[1], body: data, bodyOffset: padded}
	d := &decoder{data: data[:headerLen], pos: 16}
	for d.pos < headerLen {
		if err := d.align(8); err != nil || d.pos >= headerLen {
			break
		}
		code, err := d.byte()
		if err != nil {
			return nil, err
		}
		sig, err := d.signature()
		if err != nil {
			return nil, err
		}
		v, err := d.value(sig)
		if err != nil {
			return nil, err
		}
		switch code {
		case fieldReplySerial:
			r.replySerial, _ = v.(uint32)
		case fieldErrorName:
			r.errorName, _ = v.(string)
		case fieldSignature:
			r.signature, _ = v.(string)
		}
	}
	return r, nil
}

// call sends one fixed method call and returns the decoder positioned at the
// reply body. Messages that are not the reply (for example signals) are skipped.
// send writes one method call with the next serial and SCM_CREDENTIALS.
func (c *dbusConn) send(path, iface, member, sig string, args ...string) error {
	return c.sendBody(path, iface, member, sig, stringsBody(args))
}

func (c *dbusConn) sendBody(path, iface, member, sig string, body *encoder) error {
	c.serial++
	fields := []headerField{
		{fieldPath, "o", path},
		{fieldInterface, "s", iface},
		{fieldMember, "s", member},
		// No DESTINATION: this is a direct (peer-to-peer) connection, not a bus.
	}
	if _, _, err := c.conn.WriteMsgUnix(encodeMessage(c.serial, fields, sig, body), credentials(), nil); err != nil {
		return fmt.Errorf("send %s: %w", member, err)
	}
	return nil
}

func (c *dbusConn) call(path, iface, member, sig string, args ...string) (*decoder, string, error) {
	return c.callBody(path, iface, member, sig, stringsBody(args))
}

// callTimeout bounds one method call round trip. Each call sets its own
// deadline, so a long transient run (many short calls) never hits the dial
// deadline.
var callTimeout = 20 * time.Second

func (c *dbusConn) callBody(path, iface, member, sig string, body *encoder) (*decoder, string, error) {
	if err := c.conn.SetDeadline(time.Now().Add(callTimeout)); err != nil {
		return nil, "", err
	}
	if err := c.sendBody(path, iface, member, sig, body); err != nil {
		return nil, "", err
	}
	for {
		r, err := c.readMessage()
		if err != nil {
			return nil, "", err
		}
		if (r.kind != msgMethodReturn && r.kind != msgError) || r.replySerial != c.serial {
			continue
		}
		d := &decoder{data: r.body, pos: r.bodyOffset}
		if r.kind == msgError {
			text := ""
			if strings.HasPrefix(r.signature, "s") {
				text, _ = d.string()
			}
			return nil, "", fmt.Errorf("%s failed: %s %s", member, r.errorName, text)
		}
		return d, r.signature, nil
	}
}

const (
	managerPath  = "/org/freedesktop/systemd1"
	managerIface = "org.freedesktop.systemd1.Manager"
	unitIface    = "org.freedesktop.systemd1.Unit"
	serviceIface = "org.freedesktop.systemd1.Service"
	propsIface   = "org.freedesktop.DBus.Properties"
)

func (c *dbusConn) objectCall(member, unit string, extra ...string) (string, error) {
	d, sig, err := c.call(managerPath, managerIface, member, "s"+strings.Repeat("s", len(extra)), append([]string{unit}, extra...)...)
	if err != nil {
		return "", err
	}
	if sig != "o" {
		return "", fmt.Errorf("%s returned signature %q, want o", member, sig)
	}
	return d.string()
}

func (c *dbusConn) property(path, iface, name string) (any, error) {
	d, sig, err := c.call(path, propsIface, "Get", "ss", iface, name)
	if err != nil {
		return nil, err
	}
	if sig != "v" {
		return nil, fmt.Errorf("property %s returned signature %q, want v", name, sig)
	}
	return d.value("v")
}

type unitState struct {
	load, active, sub string
	restarts          uint32
	activeEnterMonoUs uint64
}

func probe(c *dbusConn, unit string) (unitState, error) {
	path, err := c.objectCall("LoadUnit", unit)
	if err != nil {
		return unitState{}, err
	}
	var s unitState
	for _, p := range []struct {
		name string
		into any
	}{{"LoadState", &s.load}, {"ActiveState", &s.active}, {"SubState", &s.sub}, {"ActiveEnterTimestampMonotonic", &s.activeEnterMonoUs}} {
		v, err := c.property(path, unitIface, p.name)
		if err != nil {
			return unitState{}, err
		}
		switch target := p.into.(type) {
		case *string:
			value, ok := v.(string)
			if !ok {
				return unitState{}, fmt.Errorf("%s has unexpected type", p.name)
			}
			*target = value
		case *uint64:
			value, ok := v.(uint64)
			if !ok {
				return unitState{}, fmt.Errorf("%s has unexpected type", p.name)
			}
			*target = value
		}
	}
	// NRestarts lives on the Service interface; read it only for loaded services.
	if s.load == "loaded" {
		d, sig, err := c.call(path, propsIface, "Get", "ss", serviceIface, "NRestarts")
		if err == nil && sig == "v" {
			if v, err := d.value("v"); err == nil {
				s.restarts, _ = v.(uint32)
			}
		}
	}
	return s, nil
}

func run(r request, socket string) error {
	c, err := dialSystemd(socket, os.Getuid(), 20*time.Second)
	if err != nil {
		return err
	}
	defer c.close()
	switch r.command {
	case "probe":
		s, err := probe(c, r.unit)
		if err != nil {
			return err
		}
		fmt.Printf("unit=%s load_state=%s active_state=%s sub_state=%s n_restarts=%d active_enter_monotonic_us=%d\n",
			r.unit, s.load, s.active, s.sub, s.restarts, s.activeEnterMonoUs)
	case "restart":
		s, err := probe(c, r.unit)
		if err != nil {
			return err
		}
		if s.load != "loaded" {
			return fmt.Errorf("unit %s is %s on this node; nothing was restarted", r.unit, s.load)
		}
		job, err := c.objectCall("RestartUnit", r.unit, "replace")
		if err != nil {
			return err
		}
		fmt.Printf("unit=%s restart_job=%s\n", r.unit, job)
	case "netplan-sriov-apply", "netplan-rebind":
		return runTransient(c, r.transientUnit(), r.argv(), transientTimeout)
	}
	return nil
}

// transientTimeout bounds one netplan run; the session deadline still applies.
// The node-maintenance capture bound of the netplan steps is set above it.
const transientTimeout = 2 * time.Minute

// transientStopTimeout bounds the stop of a timed-out or leftover unit.
const transientStopTimeout = 15 * time.Second

// transientStartSlack is how much longer than the helper's own run timeout
// systemd lets a transient command run before it stops it.
const transientStartSlack = 5 * time.Second

// microseconds converts a duration to the unsigned microseconds systemd
// expects; a negative duration becomes 0.
func microseconds(d time.Duration) uint64 {
	us := d.Microseconds()
	if us < 0 {
		return 0
	}
	return uint64(us)
}

// transientUnitBody encodes StartTransientUnit(name, "fail", properties, [])
// for a oneshot service that runs argv once and stays loaded afterwards
// (RemainAfterExit), so that its Result and ExecMainStatus can be read.
// TimeoutStartUSec lets systemd itself stop a command that outlives the run
// timeout, also when the helper was killed before it could stop the unit.
func transientUnitBody(unit string, argv []string, timeout time.Duration) *encoder {
	e := &encoder{}
	e.string(unit)
	e.string("fail")
	propsLen, propsStart := e.beginArray(8) // a(sv)
	prop := func(name, sig string) {
		e.align(8)
		e.string(name)
		e.signature(sig)
	}
	prop("Description", "s")
	e.string("Breakglass node-maintenance: " + strings.Join(argv, " "))
	prop("Type", "s")
	e.string("oneshot")
	prop("RemainAfterExit", "b")
	e.uint32(1)
	// Stopping a command that ignores SIGTERM ends with SIGKILL after 15 s,
	// inside the 30 s the helper waits for the unit to unload.
	prop("TimeoutStopUSec", "t")
	e.uint64(uint64(transientStopTimeout / time.Microsecond))
	prop("TimeoutStartUSec", "t")
	e.uint64(microseconds(timeout + transientStartSlack))
	prop("ExecStart", "a(sasb)")
	execLen, execStart := e.beginArray(8)
	e.align(8)
	e.string(argv[0])
	argvLen, argvStart := e.beginArray(4)
	for _, arg := range argv {
		e.string(arg)
	}
	e.endArray(argvLen, argvStart)
	e.uint32(0) // ignore failure: false
	e.endArray(execLen, execStart)
	e.endArray(propsLen, propsStart)
	auxLen, auxStart := e.beginArray(8) // a(sa(sv)): no auxiliary units
	e.endArray(auxLen, auxStart)
	return e
}

// clearTransient stops or resets a loaded unit of the fixed name and waits
// until systemd unloaded it, so the name can be reused. Before a run (leftover
// true) it reports what it clears: an earlier run was interrupted.
func clearTransient(c *dbusConn, unit string, deadline time.Time, leftover bool) error {
	for {
		s, err := probe(c, unit)
		if err != nil {
			return err
		}
		if s.load == "not-found" {
			return nil
		}
		if leftover {
			fmt.Fprintf(os.Stderr, "service-action: clearing leftover unit %s (%s/%s) of an interrupted run\n", unit, s.load, s.active)
			leftover = false
		}
		if s.active == "active" || s.active == "activating" {
			_, _ = c.objectCall("StopUnit", unit, "replace")
		} else {
			_, _, _ = c.call(managerPath, managerIface, "ResetFailedUnit", "s", unit)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("transient unit %s is still loaded (%s/%s)", unit, s.load, s.active)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// runTransient runs one fixed host command as a transient oneshot unit and
// succeeds only if it exited 0 within timeout. The unit is always unloaded
// again (stopped first if it still runs); its output stays in the host journal.
func runTransient(c *dbusConn, unit string, argv []string, timeout time.Duration) (err error) {
	deadline := time.Now().Add(timeout)
	if err := clearTransient(c, unit, deadline, true); err != nil {
		return err
	}
	d, sig, err := c.callBody(managerPath, managerIface, "StartTransientUnit", "ssa(sv)a(sa(sv))", transientUnitBody(unit, argv, timeout))
	if err != nil {
		return err
	}
	defer func() {
		if clearErr := clearTransient(c, unit, time.Now().Add(30*time.Second), false); clearErr != nil {
			fmt.Fprintf(os.Stderr, "service-action: %v\n", clearErr)
			// A run that succeeded but left its unit loaded is reported.
			if err == nil {
				err = clearErr
			}
		}
	}()
	if sig != "o" {
		return fmt.Errorf("StartTransientUnit returned signature %q, want o", sig)
	}
	job, err := d.string()
	if err != nil {
		return err
	}
	path, err := c.objectCall("LoadUnit", unit)
	if err != nil {
		return err
	}
	state := ""
	for {
		v, err := c.property(path, unitIface, "ActiveState")
		if err != nil {
			return err
		}
		state, _ = v.(string)
		if state == "active" || state == "failed" || time.Now().After(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	command := strings.Join(argv, " ")
	if state != "active" && state != "failed" {
		fmt.Printf("unit=%s job=%s command=%q active_state=%s result=- exec_main_status=-\n", unit, job, command, state)
		return fmt.Errorf("%s did not finish within %s (active_state=%s); the unit is stopped", command, timeout, state)
	}
	result, status := "", int32(-1)
	if v, err := c.property(path, serviceIface, "Result"); err == nil {
		result, _ = v.(string)
	}
	if v, err := c.property(path, serviceIface, "ExecMainStatus"); err == nil {
		status, _ = v.(int32)
	}
	fmt.Printf("unit=%s job=%s command=%q active_state=%s result=%s exec_main_status=%d\n", unit, job, command, state, result, status)
	if state != "active" || result != "success" || status != 0 {
		return fmt.Errorf("%s did not succeed (active_state=%s result=%s exec_main_status=%d)", command, state, result, status)
	}
	return nil
}
