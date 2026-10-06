// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
)

func TestEscalationDisplayNameRoundTrip(t *testing.T) {
	s := helpers.SetupTest(t)
	token := s.TC.OIDCProvider().GetRequesterToken(t, s.Ctx)
	apiClient := NewEscalationAPIClient(token)

	for _, tc := range []struct {
		name        string
		displayName string
	}{
		{name: "ExplicitDisplayName", displayName: "Emergency Admin Display Name E2E"},
		{name: "MetadataNameFallback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			escalation := helpers.NewEscalationBuilder(s.GenerateName("e2e-display-name"), s.Namespace).
				WithAllowedClusters(s.Cluster).
				WithEscalatedGroup("e2e-display-name-group").
				Build()
			escalation.Spec.DisplayName = tc.displayName
			require.NoError(t, s.CreateResource(escalation))

			var persisted breakglassv1alpha1.BreakglassEscalation
			require.NoError(t, s.Client.Get(s.Ctx, client.ObjectKeyFromObject(escalation), &persisted))
			require.Equal(t, tc.displayName, persisted.Spec.DisplayName, "API server must preserve the optional field")
			helpers.WaitForEscalationReady(t, s.Ctx, s.Client, escalation.Name, escalation.Namespace, time.Minute)

			expectedDisplay := escalation.GetDisplayName()
			require.Eventually(t, func() bool {
				escalations, status, err := apiClient.ListEscalations(s.Ctx, nil)
				if err != nil || status != http.StatusOK {
					return false
				}
				for _, item := range escalations {
					if item.Name == escalation.Name {
						return item.Spec.DisplayName == expectedDisplay && item.Spec.EscalatedGroup == escalation.Spec.EscalatedGroup
					}
				}
				return false
			}, time.Minute, time.Second, "REST list must return resource identity and resolved display name")

			var output bytes.Buffer
			root := bgctlcmd.NewRootCommand(bgctlcmd.Config{OutputWriter: &output})
			root.SetArgs([]string{"--server", helpers.GetAPIBaseURL(), "--token", token, "escalation", "list", "-o", "table"})
			require.NoError(t, root.ExecuteContext(s.Ctx))
			require.Contains(t, output.String(), "DISPLAY_NAME")
			var row string
			for _, line := range strings.Split(output.String(), "\n") {
				fields := strings.Fields(line)
				if len(fields) > 0 && fields[0] == escalation.Name {
					row = line
					break
				}
			}
			require.NotEmpty(t, row, "bgctl must preserve the resource name in NAME")
			require.True(t, strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(row, escalation.Name)), expectedDisplay),
				"bgctl must render the resolved name in DISPLAY_NAME: %s", row)

			require.NoError(t, s.Client.Get(s.Ctx, client.ObjectKeyFromObject(escalation), &persisted))
			require.Equal(t, tc.displayName, persisted.Spec.DisplayName, "response fallback must not be persisted")
		})
	}
}
