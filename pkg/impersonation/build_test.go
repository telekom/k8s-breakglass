// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package impersonation

import (
	"reflect"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
)

// TestBuild_LegacyIsByteIdenticalToPreFeatureBehaviour is the core
// backwards-compatibility test. On a spoke without constrained impersonation, the
// wire format must be exactly what breakglass has always sent.
func TestBuild_LegacyIsByteIdenticalToPreFeatureBehaviour(t *testing.T) {
	// This is verbatim what pkg/breakglass/group_checker.go used to construct.
	wantLegacy := rest.ImpersonationConfig{
		UserName: "system:auth-checker",
		Groups:   []string{"cluster-admins", "sre"},
	}

	identity := Identity{
		UserName: "system:auth-checker",
		Groups:   []string{"cluster-admins", "sre"},
	}

	unsupported := Capability{Support: SupportNo, DetectedVia: "probe-denied", ServerVersion: "v1.31.0"}

	// A constrained mode requested against an unsupported spoke must produce the
	// legacy config, not an error and not a stripped identity.
	got, err := Build(identity, ModeUserInfo, unsupported)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if !reflect.DeepEqual(got.Config, wantLegacy) {
		t.Errorf("downgraded config = %+v, want %+v", got.Config, wantLegacy)
	}
	if got.Mode != ModeLegacy {
		t.Errorf("Mode = %q, want legacy", got.Mode)
	}
	if !got.Downgraded {
		t.Error("Downgraded = false, want true")
	}
	if got.DowngradeReason == "" {
		t.Error("DowngradeReason is empty")
	}
	// Legacy carries no constraint, mirroring the apiserver omitting the audit field.
	if got.Constraint != "" {
		t.Errorf("Constraint = %q, want empty for legacy", got.Constraint)
	}

	// Explicitly requesting legacy must produce the same thing.
	explicit, err := Build(identity, ModeLegacy, Capability{Support: SupportYes})
	if err != nil {
		t.Fatalf("Build(legacy) returned error: %v", err)
	}
	if !reflect.DeepEqual(explicit.Config, wantLegacy) {
		t.Errorf("explicit legacy config = %+v, want %+v", explicit.Config, wantLegacy)
	}
	if explicit.Downgraded {
		t.Error("explicitly-requested legacy marked as Downgraded")
	}
}

func TestBuild_UserInfoCarriesAllFields(t *testing.T) {
	identity := Identity{
		UserName: "jane@example.com",
		UID:      "uid-1",
		Groups:   []string{"devs"},
		Extra:    map[string][]string{"example.com/k": {"v"}},
	}

	got, err := Build(identity, ModeUserInfo, Capability{Support: SupportYes})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if got.Config.UserName != "jane@example.com" {
		t.Errorf("UserName = %q", got.Config.UserName)
	}
	if got.Config.UID != "uid-1" {
		t.Errorf("UID = %q, want uid-1: user-info is the only mode that carries a UID", got.Config.UID)
	}
	if !reflect.DeepEqual(got.Config.Groups, []string{"devs"}) {
		t.Errorf("Groups = %v", got.Config.Groups)
	}
	if !reflect.DeepEqual(got.Config.Extra, map[string][]string{"example.com/k": {"v"}}) {
		t.Errorf("Extra = %v", got.Config.Extra)
	}
	if got.Mode != ModeUserInfo {
		t.Errorf("Mode = %q", got.Mode)
	}
	if got.Constraint != "impersonate:user-info" {
		t.Errorf("Constraint = %q, want impersonate:user-info", got.Constraint)
	}
}

// TestBuild_NodeAndSAModesSetOnlyUsername asserts Build cannot emit a config that
// trips the apiserver's onlyUsernameSet precondition.
func TestBuild_NodeAndSAModesSetOnlyUsername(t *testing.T) {
	tests := []struct {
		mode     Mode
		username string
	}{
		{ModeServiceAccount, "system:serviceaccount:kube-system:probe"},
		{ModeArbitraryNode, "system:node:worker-1"},
		{ModeAssociatedNode, "system:node:worker-1"},
	}

	for _, tc := range tests {
		t.Run(string(tc.mode), func(t *testing.T) {
			got, err := Build(Identity{UserName: tc.username}, tc.mode, Capability{Support: SupportYes})
			if err != nil {
				t.Fatalf("Build returned error: %v", err)
			}

			if got.Config.UserName != tc.username {
				t.Errorf("UserName = %q, want %q", got.Config.UserName, tc.username)
			}
			if got.Config.UID != "" {
				t.Errorf("UID = %q, want empty: it would disable constrained mode", got.Config.UID)
			}
			if len(got.Config.Groups) != 0 {
				t.Errorf("Groups = %v, want empty: it would disable constrained mode", got.Config.Groups)
			}
			if len(got.Config.Extra) != 0 {
				t.Errorf("Extra = %v, want empty: it would disable constrained mode", got.Config.Extra)
			}

			// The result must actually select the intended mode.
			built := Identity{UserName: got.Config.UserName}
			requestorNode := ""
			if tc.mode == ModeAssociatedNode {
				requestorNode = "worker-1"
			}
			if selected := built.SelectMode(requestorNode); selected != tc.mode {
				t.Errorf("the built config selects mode %q, not the requested %q", selected, tc.mode)
			}
		})
	}
}

func TestBuild_RejectsInvalidIdentity(t *testing.T) {
	tests := []struct {
		name     string
		identity Identity
		mode     Mode
		wantMsg  string
	}{
		{
			"system:masters",
			Identity{UserName: "jane", Groups: []string{GroupSystemMasters}},
			ModeUserInfo,
			"system:masters",
		},
		{
			"SA mode with uid (mixing trap)",
			Identity{UserName: "system:serviceaccount:ns:sa", UID: "u1"},
			ModeServiceAccount,
			"legacy",
		},
		{
			"user-info with node username",
			Identity{UserName: "system:node:w1"},
			ModeUserInfo,
			"refuses node usernames",
		},
		{
			"node mode with groups",
			Identity{UserName: "system:node:w1", Groups: []string{"g"}},
			ModeArbitraryNode,
			"groups cannot be impersonated",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Build(tc.identity, tc.mode, Capability{Support: SupportYes})
			if err == nil {
				t.Fatalf("Build accepted an invalid identity for mode %q", tc.mode)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tc.wantMsg)
			}
		})
	}
}

// TestBuild_UnknownCapabilityAttemptsConstrained asserts the "never fail closed on
// unknown" rule.
func TestBuild_UnknownCapabilityAttemptsConstrained(t *testing.T) {
	identity := Identity{UserName: "jane", Groups: []string{"devs"}}

	for _, capability := range []Capability{{}, {Support: SupportUnknown}} {
		got, err := Build(identity, ModeUserInfo, capability)
		if err != nil {
			t.Fatalf("Build returned error: %v", err)
		}
		if got.Mode != ModeUserInfo {
			t.Errorf("Mode = %q, want user-info: unknown capability must attempt the "+
				"constrained path so the fallback decides", got.Mode)
		}
		if got.Downgraded {
			t.Error("Downgraded = true for unknown capability")
		}
	}
}

func TestBuild_EmptyModeDefaultsToLegacy(t *testing.T) {
	got, err := Build(Identity{UserName: "jane"}, "", Capability{Support: SupportYes})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if got.Mode != ModeLegacy {
		t.Errorf("Mode = %q, want legacy for an empty requested mode", got.Mode)
	}
}

// TestBuild_DoesNotAliasInputSlices guards against a caller mutating the identity
// afterwards and silently changing an in-flight impersonation config.
func TestBuild_DoesNotAliasInputSlices(t *testing.T) {
	groups := []string{"devs"}
	extra := map[string][]string{"example.com/k": {"v"}}
	identity := Identity{UserName: "jane", Groups: groups, Extra: extra}

	got, err := Build(identity, ModeUserInfo, Capability{Support: SupportYes})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	groups[0] = "mutated"
	extra["example.com/k"][0] = "mutated"

	if got.Config.Groups[0] != "devs" {
		t.Error("Build aliased the input groups slice")
	}
	if got.Config.Extra["example.com/k"][0] != "v" {
		t.Error("Build aliased the input extra values")
	}
}

func TestBuild_LegacyDoesNotAliasInputSlices(t *testing.T) {
	groups := []string{"devs"}
	identity := Identity{UserName: "jane", Groups: groups}

	got, err := Build(identity, ModeLegacy, Capability{})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	groups[0] = "mutated"
	if got.Config.Groups[0] != "devs" {
		t.Error("legacy Build aliased the input groups slice")
	}
}

func TestBuild_DowngradeReasonMentionsDetection(t *testing.T) {
	got, err := Build(
		Identity{UserName: "jane"},
		ModeUserInfo,
		Capability{Support: SupportNo, DetectedVia: "probe-denied", ServerVersion: "v1.31.0"},
	)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if !strings.Contains(got.DowngradeReason, "probe-denied") {
		t.Errorf("DowngradeReason %q does not name the detection method", got.DowngradeReason)
	}
	if !strings.Contains(got.DowngradeReason, "v1.31.0") {
		t.Errorf("DowngradeReason %q does not name the server version", got.DowngradeReason)
	}

	// With no detection info the message must still be intelligible.
	bare, err := Build(Identity{UserName: "jane"}, ModeUserInfo, Capability{Support: SupportNo})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if !strings.Contains(bare.DowngradeReason, "no detection yet") {
		t.Errorf("bare DowngradeReason = %q", bare.DowngradeReason)
	}
}
