//go:build e2e_convergence

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type convergenceIdentityCases struct {
	GroupClaim               string `json:"groupClaim"`
	CompatibilityGroupPrefix string `json:"compatibilityGroupPrefix"`
}

func TestConvergenceIdentityGroupMapping(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithTimeout(5*time.Minute))
	ctx := s.Ctx
	fixture, err := os.ReadFile(filepath.Join("..", "fixtures", "convergence-identity", "cases.yaml"))
	require.NoError(t, err)
	var cases convergenceIdentityCases
	require.NoError(t, yaml.Unmarshal(fixture, &cases))
	require.NotEmpty(t, cases.GroupClaim)
	require.NotEmpty(t, cases.CompatibilityGroupPrefix)

	user := helpers.TestUsers.PlatformIdentityRequester
	token := s.TC.OIDCProvider().GetTokenForUser(t, ctx, user)
	groups := oidcClaimStrings(t, token, cases.GroupClaim)
	require.NotEmpty(t, user.Groups, "the test identity must define its expected groups")
	group := user.Groups[0]
	require.Contains(t, groups, group, "the authenticated token must carry the configured group")

	createTemplate := func(suffix string) *breakglassv1alpha1.DebugSessionTemplate {
		t.Helper()
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("identity-" + suffix)},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Identity mapping check", Mode: breakglassv1alpha1.DebugSessionModeWorkload,
				TargetNamespace: "breakglass-debug",
				PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: debug
    image: busybox:1.37
    command: ["sleep", "600"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 65532
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
`,
			},
		}
		require.NoError(t, s.CreateResource(template))
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("identity-" + suffix), Namespace: s.Namespace},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
				Clusters:    []string{s.Cluster},
				Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Groups: []string{group}},
				Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Users: []string{helpers.TestUsers.DebugSessionApprover.Email}},
			},
		}
		if suffix == "prefixed" {
			binding.Spec.Allowed.Groups = []string{cases.CompatibilityGroupPrefix + group}
		}
		require.NoError(t, s.CreateResource(binding))
		return template
	}
	matched := createTemplate("matched")
	unmatched := createTemplate("prefixed")
	api := NewDebugSessionAPIClient(token)

	// includeUnavailable keeps cluster availability out of the decision, so the
	// prefixed template can only be hidden by group authorization.
	require.Eventually(t, func() bool {
		items, status, err := api.ListTemplatesWithOptions(ctx, t, true)
		if err != nil || status != 200 {
			return false
		}
		foundMatched, foundUnmatched := false, false
		for _, item := range items {
			foundMatched = foundMatched || item.Name == matched.Name
			foundUnmatched = foundUnmatched || item.Name == unmatched.Name
		}
		return foundMatched && !foundUnmatched
	}, helpers.WaitForStateTimeout, time.Second, "authorization must match the token group exactly and reject the prefixed compatibility variant")
	_, status, err := api.GetTemplate(ctx, t, unmatched.Name)
	require.Error(t, err)
	require.Contains(t, []int{403, 404}, status)
}

func oidcClaimStrings(t *testing.T, token, claim string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "OIDC token must be a JWT")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(payload, &claims))
	var values []string
	require.NoError(t, json.Unmarshal(claims[claim], &values), "JWT claim %q must be a string array", claim)
	return values
}
