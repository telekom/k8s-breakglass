// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	netlinkHeaderLength   = 16
	ifInfoMessageLength   = 16
	neighborMessageLength = 12
	netlinkRequest        = 0x1
	netlinkAck            = 0x4
	netlinkReplace        = 0x100
	netlinkCreate         = 0x400
	netlinkError          = 0x2
	rtmNewLink            = 16
	rtmGetLink            = 18
	rtmNewNeighbor        = 28
	iflaIfname            = 3
	iflaMaster            = 10
	iflaLinkInfo          = 18
	iflaInfoKind          = 1
	ndaDestination        = 1
	ndaLinkLayerAddress   = 2
	ndaVLAN               = 5
	interfaceFlagUp       = 0x1
	neighborReachable     = 0x2
	neighborNoARP         = 0x40
	neighborFlagMaster    = 0x4
	addressFamilyBridge   = 7
	siocEthtool           = 0x8946
	ethtoolNwayReset      = 0x9
)

type linkIdentity struct {
	name   string
	master uint32
	kind   string
}

type routeNetlink struct {
	fd  int
	seq uint32
}

func execute(request actionRequest) error {
	connection, err := openRouteNetlink()
	if err != nil {
		return err
	}
	defer connection.close()

	switch request.action {
	case actionLinkCycle:
		if _, err := connection.getLink(request.ifindex); err != nil {
			return fmt.Errorf("resolve pinned ifindex %d: %w", request.ifindex, err)
		}
		if err := connection.setLinkUp(request.ifindex, false); err != nil {
			return fmt.Errorf("take pinned ifindex %d down: %w", request.ifindex, err)
		}
		fmt.Printf("ifindex=%d state=down\n", request.ifindex)
		if err := connection.setLinkUp(request.ifindex, true); err != nil {
			return fmt.Errorf("bring pinned ifindex %d up: %w", request.ifindex, err)
		}
		fmt.Printf("ifindex=%d state=up\n", request.ifindex)
	case actionRestartAutonegotiation:
		identity, err := connection.getLink(request.ifindex)
		if err != nil {
			return fmt.Errorf("resolve pinned ifindex %d: %w", request.ifindex, err)
		}
		if err := restartAutonegotiation(identity.name); err != nil {
			return fmt.Errorf("restart auto-negotiation for pinned ifindex %d: %w", request.ifindex, err)
		}
		current, err := connection.getLink(request.ifindex)
		if err != nil || current.name != identity.name {
			return fmt.Errorf("pinned ifindex %d changed during auto-negotiation request", request.ifindex)
		}
		fmt.Printf("ifindex=%d auto_negotiation=restarted\n", request.ifindex)
	case actionNeighborReplace:
		if _, err := connection.getLink(request.ifindex); err != nil {
			return fmt.Errorf("resolve pinned ifindex %d: %w", request.ifindex, err)
		}
		if err := connection.replaceNeighbor(request); err != nil {
			return fmt.Errorf("replace neighbor on pinned ifindex %d: %w", request.ifindex, err)
		}
		fmt.Printf("ifindex=%d neighbor=%s mac=%s state=reachable\n", request.ifindex, request.address, request.mac)
	case actionBridgeFDBReplace:
		master, err := connection.getLink(request.masterIfindex)
		if err != nil {
			return fmt.Errorf("resolve pinned master ifindex %d: %w", request.masterIfindex, err)
		}
		if master.kind != "bridge" {
			return fmt.Errorf("pinned master ifindex %d is not a bridge", request.masterIfindex)
		}
		port, err := connection.getLink(request.ifindex)
		if err != nil {
			return fmt.Errorf("resolve pinned port ifindex %d: %w", request.ifindex, err)
		}
		if port.master != request.masterIfindex {
			return fmt.Errorf("pinned port ifindex %d is attached to master ifindex %d, not approved master ifindex %d", request.ifindex, port.master, request.masterIfindex)
		}
		if err := connection.replaceBridgeFDB(request); err != nil {
			return fmt.Errorf("replace bridge FDB entry on pinned port ifindex %d: %w", request.ifindex, err)
		}
		port, err = connection.getLink(request.ifindex)
		if err != nil || port.master != request.masterIfindex {
			return fmt.Errorf("pinned port ifindex %d changed master during bridge FDB request", request.ifindex)
		}
		fmt.Printf("port_ifindex=%d master_ifindex=%d mac=%s vlan=%d state=static\n", request.ifindex, request.masterIfindex, request.mac, request.vlan)
	default:
		return fmt.Errorf("internal unsupported action %q", request.action)
	}
	return nil
}

func openRouteNetlink() (*routeNetlink, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open rtnetlink socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("bind rtnetlink socket: %w", err)
	}
	return &routeNetlink{fd: fd}, nil
}

func (connection *routeNetlink) close() {
	_ = syscall.Close(connection.fd)
}

func (connection *routeNetlink) getLink(ifindex uint32) (linkIdentity, error) {
	payload := make([]byte, ifInfoMessageLength)
	payload[0] = syscall.AF_UNSPEC
	binary.NativeEndian.PutUint32(payload[4:8], ifindex)
	reply, err := connection.request(rtmGetLink, netlinkRequest, payload, rtmNewLink)
	if err != nil {
		return linkIdentity{}, err
	}
	if len(reply) < ifInfoMessageLength {
		return linkIdentity{}, errors.New("short RTM_NEWLINK response")
	}
	actualIfindex := binary.NativeEndian.Uint32(reply[4:8])
	if actualIfindex != ifindex {
		return linkIdentity{}, fmt.Errorf("kernel returned ifindex %d for requested ifindex %d", actualIfindex, ifindex)
	}
	attributes, err := parseNetlinkAttributes(reply[ifInfoMessageLength:])
	if err != nil {
		return linkIdentity{}, err
	}
	identity := linkIdentity{}
	if name := attributes[iflaIfname]; len(name) > 0 {
		identity.name = string(bytes.TrimRight(name, "\x00"))
	}
	if master := attributes[iflaMaster]; len(master) == 4 {
		identity.master = binary.NativeEndian.Uint32(master)
	}
	if linkInfo := attributes[iflaLinkInfo]; len(linkInfo) > 0 {
		nested, nestedErr := parseNetlinkAttributes(linkInfo)
		if nestedErr != nil {
			return linkIdentity{}, fmt.Errorf("parse link-info attributes: %w", nestedErr)
		}
		identity.kind = string(bytes.TrimRight(nested[iflaInfoKind], "\x00"))
	}
	if identity.name == "" {
		return linkIdentity{}, errors.New("RTM_NEWLINK response omitted interface name")
	}
	return identity, nil
}

func (connection *routeNetlink) setLinkUp(ifindex uint32, up bool) error {
	payload := make([]byte, ifInfoMessageLength)
	payload[0] = syscall.AF_UNSPEC
	binary.NativeEndian.PutUint32(payload[4:8], ifindex)
	if up {
		binary.NativeEndian.PutUint32(payload[8:12], interfaceFlagUp)
	}
	binary.NativeEndian.PutUint32(payload[12:16], interfaceFlagUp)
	_, err := connection.request(rtmNewLink, netlinkRequest|netlinkAck, payload, 0)
	return err
}

func (connection *routeNetlink) replaceNeighbor(request actionRequest) error {
	payload := make([]byte, neighborMessageLength)
	if request.family == 4 {
		payload[0] = syscall.AF_INET
		request.address = request.address.To4()
	} else {
		payload[0] = syscall.AF_INET6
		request.address = request.address.To16()
	}
	binary.NativeEndian.PutUint32(payload[4:8], request.ifindex)
	binary.NativeEndian.PutUint16(payload[8:10], neighborReachable)
	payload = appendAttribute(payload, ndaDestination, request.address)
	payload = appendAttribute(payload, ndaLinkLayerAddress, request.mac)
	_, err := connection.request(rtmNewNeighbor, netlinkRequest|netlinkAck|netlinkCreate|netlinkReplace, payload, 0)
	return err
}

func (connection *routeNetlink) replaceBridgeFDB(request actionRequest) error {
	payload := make([]byte, neighborMessageLength)
	payload[0] = addressFamilyBridge
	binary.NativeEndian.PutUint32(payload[4:8], request.ifindex)
	binary.NativeEndian.PutUint16(payload[8:10], neighborNoARP)
	payload[10] = neighborFlagMaster
	payload = appendAttribute(payload, ndaLinkLayerAddress, request.mac)
	vlan := make([]byte, 2)
	binary.NativeEndian.PutUint16(vlan, request.vlan)
	payload = appendAttribute(payload, ndaVLAN, vlan)
	_, err := connection.request(rtmNewNeighbor, netlinkRequest|netlinkAck|netlinkCreate|netlinkReplace, payload, 0)
	return err
}

func (connection *routeNetlink) request(messageType uint16, flags uint16, payload []byte, expectedType uint16) ([]byte, error) {
	connection.seq++
	request := make([]byte, netlinkHeaderLength+len(payload))
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], messageType)
	binary.NativeEndian.PutUint16(request[6:8], flags)
	binary.NativeEndian.PutUint32(request[8:12], connection.seq)
	copy(request[netlinkHeaderLength:], payload)
	if err := syscall.Sendto(connection.fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("send netlink request: %w", err)
	}
	buffer := make([]byte, 65536)
	for {
		length, sender, err := syscall.Recvfrom(connection.fd, buffer, 0)
		if err != nil {
			return nil, fmt.Errorf("receive netlink response: %w", err)
		}
		if netlinkSender, ok := sender.(*syscall.SockaddrNetlink); !ok || netlinkSender.Pid != 0 {
			continue
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:length])
		if err != nil {
			return nil, fmt.Errorf("parse netlink response: %w", err)
		}
		for _, message := range messages {
			if message.Header.Seq != connection.seq {
				continue
			}
			if message.Header.Type == netlinkError {
				if len(message.Data) < 4 {
					return nil, errors.New("short netlink error response")
				}
				code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
				if code == 0 {
					return nil, nil
				}
				return nil, syscall.Errno(-code)
			}
			if expectedType != 0 && message.Header.Type == expectedType {
				return message.Data, nil
			}
		}
	}
}

func appendAttribute(message []byte, attributeType uint16, data []byte) []byte {
	attributeLength := 4 + len(data)
	alignedLength := align4(attributeLength)
	start := len(message)
	message = append(message, make([]byte, alignedLength)...)
	binary.NativeEndian.PutUint16(message[start:start+2], uint16(attributeLength))
	binary.NativeEndian.PutUint16(message[start+2:start+4], attributeType)
	copy(message[start+4:start+attributeLength], data)
	return message
}

func parseNetlinkAttributes(data []byte) (map[uint16][]byte, error) {
	attributes := make(map[uint16][]byte)
	for len(data) >= 4 {
		length := int(binary.NativeEndian.Uint16(data[0:2]))
		if length < 4 || length > len(data) {
			return nil, errors.New("malformed netlink attribute")
		}
		attributeType := binary.NativeEndian.Uint16(data[2:4]) & 0x3fff
		attributes[attributeType] = data[4:length]
		alignedLength := align4(length)
		if alignedLength > len(data) {
			return nil, errors.New("malformed aligned netlink attribute")
		}
		data = data[alignedLength:]
	}
	if len(data) != 0 {
		return nil, errors.New("trailing bytes in netlink attributes")
	}
	return attributes, nil
}

func align4(length int) int {
	return (length + 3) &^ 3
}

type ethtoolValue struct {
	command uint32
	data    uint32
}

type ifreqData struct {
	name    [16]byte
	data    uintptr
	padding [16]byte
}

func restartAutonegotiation(interfaceName string) error {
	if len(interfaceName) == 0 || len(interfaceName) >= len(ifreqData{}.name) {
		return errors.New("kernel interface name is invalid")
	}
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open ethtool ioctl socket: %w", err)
	}
	defer func() {
		_ = syscall.Close(socket)
	}()
	value := ethtoolValue{command: ethtoolNwayReset}
	request := ifreqData{data: uintptr(unsafe.Pointer(&value))}
	copy(request.name[:], interfaceName)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(socket), siocEthtool, uintptr(unsafe.Pointer(&request)))
	runtime.KeepAlive(value)
	if errno != 0 {
		return errno
	}
	return nil
}
