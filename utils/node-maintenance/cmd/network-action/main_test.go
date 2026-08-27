// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestParseRequestAcceptsOnlyFixedShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "link cycle", args: []string{"link-cycle", "7"}},
		{name: "restart autonegotiation", args: []string{"restart-autonegotiation", "8"}},
		{name: "IPv4 neighbor", args: []string{"neighbor-replace", "9", "4", "192.0.2.10", "02:00:00:00:00:10"}},
		{name: "IPv6 neighbor", args: []string{"neighbor-replace", "10", "6", "2001:db8::10", "02:00:00:00:00:11"}},
		{name: "bridge FDB", args: []string{"bridge-fdb-replace", "11", "12", "02:00:00:00:00:12", "4094"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseRequest(test.args); err != nil {
				t.Fatalf("parseRequest(%q) returned %v", test.args, err)
			}
		})
	}
}

func TestParseRequestRejectsExpansionAndInvalidIdentity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "arbitrary action", args: []string{"shell", "1"}},
		{name: "extra link argument", args: []string{"link-cycle", "1", "up"}},
		{name: "zero ifindex", args: []string{"link-cycle", "0"}},
		{name: "wrong family", args: []string{"neighbor-replace", "2", "5", "192.0.2.1", "02:00:00:00:00:01"}},
		{name: "family mismatch", args: []string{"neighbor-replace", "2", "6", "192.0.2.1", "02:00:00:00:00:01"}},
		{name: "multicast MAC", args: []string{"neighbor-replace", "2", "4", "192.0.2.1", "01:00:00:00:00:01"}},
		{name: "same port and master", args: []string{"bridge-fdb-replace", "3", "3", "02:00:00:00:00:01", "100"}},
		{name: "VLAN zero", args: []string{"bridge-fdb-replace", "3", "4", "02:00:00:00:00:01", "0"}},
		{name: "VLAN reserved", args: []string{"bridge-fdb-replace", "3", "4", "02:00:00:00:00:01", "4095"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseRequest(test.args); err == nil {
				t.Fatalf("parseRequest(%q) unexpectedly succeeded", test.args)
			}
		})
	}
}
