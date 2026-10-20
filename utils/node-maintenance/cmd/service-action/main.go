// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// service-action restarts or probes one allowlisted host systemd unit, or runs
// one of two fixed netplan SR-IOV commands as a transient host unit, through
// systemd's private socket. It has no generic D-Bus surface: the unit names,
// command vectors and methods are fixed in this binary.
package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const systemdPrivateSocket = "/run/systemd/private"

// allowedUnits is the complete restart allowlist. cra.service is the
// generator-made unit that owns the CRA/vSR container and its netns; on a CRA
// node containerd.service restarts it too (Requires=).
var allowedUnits = map[string]bool{
	"cra.service":        true,
	"containerd.service": true,
	"kubelet.service":    true,
}

// netplanBinary is the host netplan entrypoint. The SR-IOV commands run it on
// the host as a transient systemd unit (host mount namespace and udev), with
// argument vectors fixed in this binary; only the PF name is a parameter.
const netplanBinary = "/usr/sbin/netplan"

// interfacePattern matches a Linux interface name (IFNAMSIZ - 1 bytes).
var interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

type request struct {
	command string
	unit    string // probe/restart
	pf      string // netplan-rebind
}

const usage = "usage: service-action probe|restart UNIT | netplan-sriov-apply | netplan-rebind PF"

func parseRequest(args []string) (request, error) {
	if len(args) == 0 {
		return request{}, errors.New(usage)
	}
	r := request{command: args[0]}
	switch {
	case (r.command == "probe" || r.command == "restart") && len(args) == 2:
		r.unit = args[1]
		if !allowedUnits[r.unit] {
			return request{}, fmt.Errorf("unit %q is not allowlisted", r.unit)
		}
	case r.command == "netplan-sriov-apply" && len(args) == 1:
	case r.command == "netplan-rebind" && len(args) == 2:
		r.pf = args[1]
		if !interfacePattern.MatchString(r.pf) || r.pf == "." || r.pf == ".." || strings.HasPrefix(r.pf, "-") {
			return request{}, fmt.Errorf("interface %q is not a valid PF name", r.pf)
		}
	case r.command == "probe" || r.command == "restart" || r.command == "netplan-sriov-apply" || r.command == "netplan-rebind":
		return request{}, errors.New(usage)
	default:
		return request{}, fmt.Errorf("command %q is not allowlisted", r.command)
	}
	return r, nil
}

// transientUnit is the fixed unit name of a netplan command.
func (r request) transientUnit() string {
	if r.command == "netplan-rebind" {
		return "breakglass-netplan-rebind.service"
	}
	return "breakglass-netplan-sriov-apply.service"
}

// argv is the fixed host command of a netplan request.
func (r request) argv() []string {
	if r.command == "netplan-rebind" {
		return []string{netplanBinary, "rebind", r.pf}
	}
	return []string{netplanBinary, "apply", "--sriov-only"}
}

func main() {
	r, err := parseRequest(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "service-action: %v\n", err)
		os.Exit(2)
	}
	if err := run(r, systemdPrivateSocket); err != nil {
		fmt.Fprintf(os.Stderr, "service-action: %v\n", err)
		os.Exit(1)
	}
}
