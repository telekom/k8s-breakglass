// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
)

const (
	actionLinkCycle              = "link-cycle"
	actionRestartAutonegotiation = "restart-autonegotiation"
	actionNeighborReplace        = "neighbor-replace"
	actionBridgeFDBReplace       = "bridge-fdb-replace"
)

type actionRequest struct {
	action        string
	ifindex       uint32
	masterIfindex uint32
	family        uint8
	address       net.IP
	mac           net.HardwareAddr
	vlan          uint16
}

const (
	maximumIfindex uint32 = 1<<31 - 1
	maximumVLAN    uint16 = 4094
)

func main() {
	request, err := parseRequest(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "network-action: %v\n", err)
		os.Exit(2)
	}
	if err := execute(request); err != nil {
		fmt.Fprintf(os.Stderr, "network-action: %v\n", err)
		os.Exit(1)
	}
}

func parseRequest(args []string) (actionRequest, error) {
	var request actionRequest
	if len(args) == 0 {
		return request, errors.New("one fixed action is required")
	}
	request.action = args[0]
	switch request.action {
	case actionLinkCycle, actionRestartAutonegotiation:
		if len(args) != 2 {
			return request, fmt.Errorf("%s requires exactly IFINDEX", request.action)
		}
		ifindex, err := parsePositiveUint32("ifindex", args[1], maximumIfindex)
		if err != nil {
			return request, err
		}
		request.ifindex = ifindex
	case actionNeighborReplace:
		if len(args) != 5 {
			return request, errors.New("neighbor-replace requires exactly IFINDEX FAMILY ADDRESS MAC")
		}
		ifindex, err := parsePositiveUint32("ifindex", args[1], maximumIfindex)
		if err != nil {
			return request, err
		}
		family, err := parseAddressFamily(args[2])
		if err != nil {
			return request, err
		}
		address := net.ParseIP(args[3])
		if address == nil || (family == 4 && address.To4() == nil) || (family == 6 && address.To4() != nil) {
			return request, errors.New("address does not match the exact requested family")
		}
		mac, err := parseUnicastMAC(args[4])
		if err != nil {
			return request, err
		}
		request.ifindex = ifindex
		request.family = family
		request.address = address
		request.mac = mac
	case actionBridgeFDBReplace:
		if len(args) != 5 {
			return request, errors.New("bridge-fdb-replace requires exactly PORT_IFINDEX MASTER_IFINDEX MAC VLAN")
		}
		ifindex, err := parsePositiveUint32("port ifindex", args[1], maximumIfindex)
		if err != nil {
			return request, err
		}
		masterIfindex, err := parsePositiveUint32("master ifindex", args[2], maximumIfindex)
		if err != nil {
			return request, err
		}
		if ifindex == masterIfindex {
			return request, errors.New("port and master ifindexes must be different")
		}
		mac, err := parseUnicastMAC(args[3])
		if err != nil {
			return request, err
		}
		vlan, err := parsePositiveUint16("VLAN", args[4], maximumVLAN)
		if err != nil {
			return request, err
		}
		request.ifindex = ifindex
		request.masterIfindex = masterIfindex
		request.mac = mac
		request.vlan = vlan
	default:
		return request, fmt.Errorf("action %q is not allowlisted", request.action)
	}
	return request, nil
}

func parsePositiveUint32(label, value string, maximum uint32) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed < 1 || parsed > uint64(maximum) {
		return 0, fmt.Errorf("%s must be an integer from 1 through %d", label, maximum)
	}
	return uint32(parsed), nil
}

func parsePositiveUint16(label, value string, maximum uint16) (uint16, error) {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed < 1 || parsed > uint64(maximum) {
		return 0, fmt.Errorf("%s must be an integer from 1 through %d", label, maximum)
	}
	return uint16(parsed), nil
}

func parseAddressFamily(value string) (uint8, error) {
	parsed, err := strconv.ParseUint(value, 10, 8)
	if err != nil || (parsed != 4 && parsed != 6) {
		return 0, errors.New("address family must be exactly 4 or 6")
	}
	return uint8(parsed), nil
}

func parseUnicastMAC(value string) (net.HardwareAddr, error) {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 {
		return nil, errors.New("MAC must be an exact six-octet address")
	}
	allZero := true
	for _, octet := range mac {
		allZero = allZero && octet == 0
	}
	if allZero || mac[0]&1 != 0 {
		return nil, errors.New("MAC must be a non-zero unicast address")
	}
	return mac, nil
}
