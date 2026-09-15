// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"os"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// impersonationEnvtestClient starts an envtest API server with the generated CRDs
// installed and returns a client. Skips when envtest assets are unavailable.
func impersonationEnvtestClient(t *testing.T) ctrlclient.Client {
	t.Helper()

	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set; run 'make validate-crds' or set up envtest")
	}

	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{crdBasesDir()},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("failed to start envtest: %v", err)
	}
	t.Cleanup(func() {
		if stopErr := testEnv.Stop(); stopErr != nil {
			t.Errorf("failed to stop envtest: %v", stopErr)
		}
	})

	sch := runtime.NewScheme()
	if err := scheme.AddToScheme(sch); err != nil {
		t.Fatalf("failed to add core scheme: %v", err)
	}
	if err := AddToScheme(sch); err != nil {
		t.Fatalf("failed to add breakglass scheme: %v", err)
	}

	c, err := ctrlclient.New(cfg, ctrlclient.Options{Scheme: sch})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return c
}

// TestCRDSchema_ExistingObjectsReconcileUnchanged is the CRD-level backwards
// compatibility test required by the compatibility contract: objects that predate
// these fields must still be accepted, with the new fields simply absent.
func TestCRDSchema_ExistingObjectsReconcileUnchanged(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()

	t.Run("ClusterConfig without constrainedImpersonation", func(t *testing.T) {
		cc := &ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy-spoke", Namespace: "default"},
			Spec: ClusterConfigSpec{
				ClusterID: "legacy-spoke",
				Tenant:    "tenant-a",
			},
		}
		if err := c.Create(ctx, cc); err != nil {
			t.Fatalf("a ClusterConfig without the new field was rejected: %v", err)
		}

		got := &ClusterConfig{}
		if err := c.Get(ctx, ctrlclient.ObjectKeyFromObject(cc), got); err != nil {
			t.Fatalf("failed to read back: %v", err)
		}
		// The zero value must stay absent rather than being defaulted into existence,
		// so that "unset" remains distinguishable and the nil-receiver defaults apply.
		if got.Spec.ConstrainedImpersonation != nil {
			t.Errorf("constrainedImpersonation was defaulted to %+v; unset must stay unset",
				got.Spec.ConstrainedImpersonation)
		}
	})

	t.Run("DebugSessionTemplate with only serviceAccountRef", func(t *testing.T) {
		// This is exactly the shape ImpersonationConfig supported before this change.
		tmpl := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "pre-existing-template", Namespace: "default"},
			Spec: DebugSessionTemplateSpec{
				DisplayName: "Pre-existing",
				Impersonation: &ImpersonationConfig{
					ServiceAccountRef: &ServiceAccountReference{
						Name:      "debug-deployer",
						Namespace: "breakglass-debug",
					},
				},
			},
		}
		if err := c.Create(ctx, tmpl); err != nil {
			t.Fatalf("a pre-existing-shape template was rejected: %v", err)
		}

		got := &DebugSessionTemplate{}
		if err := c.Get(ctx, ctrlclient.ObjectKeyFromObject(tmpl), got); err != nil {
			t.Fatalf("failed to read back: %v", err)
		}
		if got.Spec.Impersonation.Mode != "" {
			t.Errorf("mode was defaulted to %q; it must stay empty so the mode is inferred",
				got.Spec.Impersonation.Mode)
		}
		if got.Spec.Impersonation.ServiceAccountRef == nil ||
			got.Spec.Impersonation.ServiceAccountRef.Name != "debug-deployer" {
			t.Error("serviceAccountRef did not round-trip")
		}
	})

	t.Run("DenyPolicy without impersonationRules", func(t *testing.T) {
		dp := &DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "pre-existing-policy"},
			Spec: DenyPolicySpec{
				Rules: []DenyRule{{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"pods"},
				}},
			},
		}
		if err := c.Create(ctx, dp); err != nil {
			t.Fatalf("a DenyPolicy without impersonationRules was rejected: %v", err)
		}
	})
}

// TestCRDSchema_ImpersonationConfigAccepted covers the accept cases for the new
// ImpersonationConfig fields.
func TestCRDSchema_ImpersonationConfigAccepted(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()

	tests := []struct {
		name string
		imp  *ImpersonationConfig
	}{
		{
			"user-info with everything",
			&ImpersonationConfig{
				Mode:              ImpersonationModeUserInfo,
				UserName:          "jane@example.com",
				UID:               "uid-1",
				Groups:            []string{"devs"},
				Extra:             map[string][]string{"example.com/scopes": {"read"}},
				AllowedIdentities: []string{"jane@example.com"},
				ActionVerbs:       []string{"get", "list"},
			},
		},
		{
			"serviceaccount mode with ref",
			&ImpersonationConfig{
				Mode:              ImpersonationModeServiceAccount,
				ServiceAccountRef: &ServiceAccountReference{Name: "probe", Namespace: "kube-system"},
			},
		},
		{
			"arbitrary-node",
			&ImpersonationConfig{Mode: ImpersonationModeArbitraryNode, UserName: "system:node:worker-1"},
		},
		{
			"associated-node",
			&ImpersonationConfig{Mode: ImpersonationModeAssociatedNode, UserName: "system:node:worker-1"},
		},
		{
			// Legacy is a legal explicit choice for pre-1.35 spokes.
			"legacy",
			&ImpersonationConfig{Mode: ImpersonationModeLegacy, UserName: "system:auth-checker"},
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := &DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "accept-" + sanitizeName(tc.name),
					Namespace: "default",
				},
				Spec: DebugSessionTemplateSpec{
					DisplayName:   tc.name,
					Impersonation: tc.imp,
				},
			}
			if err := c.Create(ctx, tmpl); err != nil {
				t.Fatalf("case %d (%s) rejected: %v", i, tc.name, err)
			}
		})
	}
}

// TestCRDSchema_ImpersonationConfigRejected covers the CEL reject cases, above all
// the header-mixing trap.
func TestCRDSchema_ImpersonationConfigRejected(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		imp     *ImpersonationConfig
		wantSub string
	}{
		// THE TRAP: uid/groups/extra alongside a ServiceAccount or node username
		// silently disables constrained impersonation.
		{
			"serviceaccount with uid",
			&ImpersonationConfig{
				Mode:              ImpersonationModeServiceAccount,
				ServiceAccountRef: &ServiceAccountReference{Name: "sa", Namespace: "ns"},
				UID:               "uid-1",
			},
			"ONLY the username",
		},
		{
			"serviceaccount with groups",
			&ImpersonationConfig{
				Mode:              ImpersonationModeServiceAccount,
				ServiceAccountRef: &ServiceAccountReference{Name: "sa", Namespace: "ns"},
				Groups:            []string{"custom"},
			},
			"ONLY the username",
		},
		{
			"serviceaccount with extra",
			&ImpersonationConfig{
				Mode:              ImpersonationModeServiceAccount,
				ServiceAccountRef: &ServiceAccountReference{Name: "sa", Namespace: "ns"},
				Extra:             map[string][]string{"ex.io/k": {"v"}},
			},
			"ONLY the username",
		},
		{
			"arbitrary-node with uid",
			&ImpersonationConfig{
				Mode:     ImpersonationModeArbitraryNode,
				UserName: "system:node:worker-1",
				UID:      "uid-1",
			},
			"ONLY the username",
		},
		{
			"associated-node with groups",
			&ImpersonationConfig{
				Mode:     ImpersonationModeAssociatedNode,
				UserName: "system:node:worker-1",
				Groups:   []string{"system:nodes"},
			},
			"ONLY the username",
		},

		// Mode / target mismatches.
		{
			"user-info with serviceAccountRef",
			&ImpersonationConfig{
				Mode:              ImpersonationModeUserInfo,
				ServiceAccountRef: &ServiceAccountReference{Name: "sa", Namespace: "ns"},
			},
			"cannot impersonate a ServiceAccount",
		},
		{
			"arbitrary-node with serviceAccountRef",
			&ImpersonationConfig{
				Mode:              ImpersonationModeArbitraryNode,
				ServiceAccountRef: &ServiceAccountReference{Name: "sa", Namespace: "ns"},
			},
			"cannot target a ServiceAccount",
		},

		// Enum enforcement: an unknown mode must be rejected by the schema.
		{
			"unknown mode",
			&ImpersonationConfig{Mode: ImpersonationMode("future-mode"), UserName: "jane"},
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := &DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "reject-" + sanitizeName(tc.name),
					Namespace: "default",
				},
				Spec: DebugSessionTemplateSpec{
					DisplayName:   tc.name,
					Impersonation: tc.imp,
				},
			}

			err := c.Create(ctx, tmpl)
			if err == nil {
				t.Fatalf("the API server accepted an invalid config (%s); on a 1.36 cluster this "+
					"would silently fall back to legacy unconstrained impersonation", tc.name)
			}
			if !apierrors.IsInvalid(err) && !apierrors.IsBadRequest(err) {
				t.Errorf("expected an Invalid/BadRequest error, got %T: %v", err, err)
			}
			if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

// TestCRDSchema_ConstrainedImpersonationConfigAccepted covers the ClusterConfig
// field, including the version-matrix settings.
func TestCRDSchema_ConstrainedImpersonationConfigAccepted(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()

	yes := true
	no := false

	tests := []struct {
		name string
		cfg  *ConstrainedImpersonationConfig
	}{
		{"empty relies on defaults", &ConstrainedImpersonationConfig{}},
		// The per-spoke version matrix: a 1.36 spoke, a pre-1.35 spoke, and an
		// autodetected one must all be expressible in the same running controller.
		{"modern spoke", &ConstrainedImpersonationConfig{
			Support:               ConstrainedImpersonationEnabled,
			LegacyFallback:        LegacyImpersonationFallbackForbidden,
			DenyUnrecognisedVerbs: &yes,
			ProbeMode:             ImpersonationModeUserInfo,
		}},
		{"pre-1.35 spoke", &ConstrainedImpersonationConfig{
			Support:        ConstrainedImpersonationDisabled,
			LegacyFallback: LegacyImpersonationFallbackAllow,
			ProbeMode:      ImpersonationModeLegacy,
		}},
		{"autodetect with warnings", &ConstrainedImpersonationConfig{
			Support:        ConstrainedImpersonationAuto,
			LegacyFallback: LegacyImpersonationFallbackWarn,
		}},
		{"deny unrecognised disabled", &ConstrainedImpersonationConfig{
			DenyUnrecognisedVerbs: &no,
		}},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cc := &ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cc-" + sanitizeName(tc.name),
					Namespace: "default",
				},
				Spec: ClusterConfigSpec{
					ClusterID:                "spoke",
					ConstrainedImpersonation: tc.cfg,
				},
			}
			if err := c.Create(ctx, cc); err != nil {
				t.Fatalf("case %d (%s) rejected: %v", i, tc.name, err)
			}
		})
	}
}

func TestCRDSchema_ConstrainedImpersonationConfigDefaults(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()

	cc := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cc-defaults", Namespace: "default"},
		Spec: ClusterConfigSpec{
			ClusterID:                "spoke",
			ConstrainedImpersonation: &ConstrainedImpersonationConfig{},
		},
	}
	if err := c.Create(ctx, cc); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	got := &ClusterConfig{}
	if err := c.Get(ctx, ctrlclient.ObjectKeyFromObject(cc), got); err != nil {
		t.Fatalf("failed to read back: %v", err)
	}

	ci := got.Spec.ConstrainedImpersonation
	if ci.Support != ConstrainedImpersonationAuto {
		t.Errorf("support defaulted to %q, want Auto", ci.Support)
	}
	// Allow, not Forbidden: existing deployments depend on the legacy fallback and a
	// stricter default would break them on upgrade.
	if ci.LegacyFallback != LegacyImpersonationFallbackAllow {
		t.Errorf("legacyFallback defaulted to %q, want Allow", ci.LegacyFallback)
	}
	if ci.DenyUnrecognisedVerbs == nil || !*ci.DenyUnrecognisedVerbs {
		t.Error("denyUnrecognisedVerbs did not default to true; a webhook that allows " +
			"unknown impersonation verbs silently grants constrained impersonation")
	}
	if ci.ProbeMode != ImpersonationModeUserInfo {
		t.Errorf("probeMode defaulted to %q, want user-info", ci.ProbeMode)
	}
}

// TestCRDSchema_ImpersonationRulesAccepted covers DenyPolicy impersonationRules.
func TestCRDSchema_ImpersonationRulesAccepted(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()

	tests := []struct {
		name  string
		rules []ImpersonationDenyRule
	}{
		{"deny all impersonation", []ImpersonationDenyRule{{}}},
		{"deny system:masters group in every mode", []ImpersonationDenyRule{{
			IdentityResources: []string{"groups"},
			Identities:        []string{"system:masters", "cluster-admins"},
			Reason:            "cluster-admin impersonation is not permitted",
		}}},
		{"close the legacy fallback", []ImpersonationDenyRule{{
			Modes: []ImpersonationMode{
				ImpersonationModeLegacy, ImpersonationModeUserInfo,
				ImpersonationModeServiceAccount, ImpersonationModeArbitraryNode,
				ImpersonationModeAssociatedNode,
			},
			IdentityResources: []string{"users"},
			Identities:        []string{"admin-*"},
		}}},
		{"deny writes under impersonation", []ImpersonationDenyRule{{
			ActionVerbs:     []string{"create", "update", "patch", "delete"},
			TargetResources: []string{"secrets"},
			TargetAPIGroups: []string{""},
		}}},
		{"deny node impersonation", []ImpersonationDenyRule{{
			Modes:             []ImpersonationMode{ImpersonationModeArbitraryNode, ImpersonationModeAssociatedNode},
			IdentityResources: []string{"nodes"},
		}}},
		{"serviceaccounts in system namespaces", []ImpersonationDenyRule{{
			IdentityResources: []string{"serviceaccounts"},
			Namespaces:        &NamespaceFilter{Patterns: []string{"kube-*"}},
		}}},
		{"userextras by key", []ImpersonationDenyRule{{
			IdentityResources: []string{"userextras"},
			ExtraKeys:         []string{"example.com/*"},
		}}},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dp := &DenyPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "dp-accept-" + sanitizeName(tc.name)},
				Spec:       DenyPolicySpec{ImpersonationRules: tc.rules},
			}
			if err := c.Create(ctx, dp); err != nil {
				t.Fatalf("case %d (%s) rejected: %v", i, tc.name, err)
			}
		})
	}
}

func TestCRDSchema_ImpersonationRulesRejected(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		rules   []ImpersonationDenyRule
		wantSub string
	}{
		{
			// The API server issues identity and action checks as separate
			// authorization requests, so such a rule could never fire.
			"identities combined with actionVerbs",
			[]ImpersonationDenyRule{{
				Identities:  []string{"jane"},
				ActionVerbs: []string{"get"},
			}},
			"separate authorization requests",
		},
		{
			"unknown identity resource",
			[]ImpersonationDenyRule{{IdentityResources: []string{"pods"}}},
			"",
		},
		{
			"unknown mode",
			[]ImpersonationDenyRule{{Modes: []ImpersonationMode{"future-mode"}}},
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dp := &DenyPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "dp-reject-" + sanitizeName(tc.name)},
				Spec:       DenyPolicySpec{ImpersonationRules: tc.rules},
			}

			err := c.Create(ctx, dp)
			if err == nil {
				t.Fatalf("the API server accepted an invalid impersonation rule (%s)", tc.name)
			}
			if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

// TestCRDSchema_DenyPolicyWithOnlyImpersonationRules asserts the spec-level CEL
// rule accepts a policy that carries impersonation rules and nothing else.
func TestCRDSchema_DenyPolicyWithOnlyImpersonationRules(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()

	dp := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "dp-impersonation-only"},
		Spec: DenyPolicySpec{
			ImpersonationRules: []ImpersonationDenyRule{{
				IdentityResources: []string{"groups"},
				Identities:        []string{"system:masters"},
			}},
		},
	}
	if err := c.Create(ctx, dp); err != nil {
		t.Fatalf("a DenyPolicy carrying only impersonationRules was rejected: %v", err)
	}

	// And a fully empty spec must still be rejected.
	emptyDP := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "dp-empty"},
		Spec:       DenyPolicySpec{},
	}
	if err := c.Create(ctx, emptyDP); err == nil {
		t.Error("an entirely empty DenyPolicy spec was accepted")
	}
}

// sanitizeName turns a test-case name into a valid Kubernetes object name.
func sanitizeName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
