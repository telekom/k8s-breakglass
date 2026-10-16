// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// service-action restarts or probes one allowlisted host systemd unit through
// systemd's private socket. It has no generic D-Bus surface: the unit names and
// the two methods are fixed in this binary.
package main

import (
	"errors"
	"fmt"
	"os"
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

type request struct {
	command string
	unit    string
}

func parseRequest(args []string) (request, error) {
	if len(args) != 2 {
		return request{}, errors.New("usage: service-action probe|restart UNIT")
	}
	r := request{command: args[0], unit: args[1]}
	if r.command != "probe" && r.command != "restart" {
		return request{}, fmt.Errorf("command %q is not allowlisted", r.command)
	}
	if !allowedUnits[r.unit] {
		return request{}, fmt.Errorf("unit %q is not allowlisted", r.unit)
	}
	return r, nil
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
