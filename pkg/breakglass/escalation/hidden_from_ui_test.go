// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package escalation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/stretchr/testify/require"
)

// TestHiddenFromUI_EscalationResponse_GroupsRemoved tests that hidden groups are not shown in API response.
func TestHiddenFromUI_EscalationResponse_GroupsRemoved(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)

	// Create escalation with hidden groups
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "admin",
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Groups:       []string{"security-team", "flm-on-duty", "on-call"},
				HiddenFromUI: []string{"flm-on-duty", "on-call"},
			},
		},
	}
	builder.WithObjects(esc)

	cli := builder.Build()
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := &BreakglassEscalationController{
		log:     logger.Sugar(),
		manager: &escmanager,
		middleware: func(c *gin.Context) {
			c.Set("email", "user@example.com")
			c.Set("groups", []string{"system:authenticated"})
			c.Next()
		},
		identityProvider: breakglass.KeycloakIdentityProvider{},
		getUserGroupsFn: func(ctx context.Context, cug breakglass.ClusterUserGroup) ([]string, error) {
			return []string{"system:authenticated"}, nil
		},
	}

	engine := gin.New()
	rg := engine.Group("/breakglassEscalations", ctrl.middleware)
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodGet, "/breakglassEscalations", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	// Parse response
	var escList []breakglassv1alpha1.BreakglassEscalation
	err := json.Unmarshal(w.Body.Bytes(), &escList)
	require.NoError(t, err)

	if len(escList) != 1 {
		t.Fatalf("expected 1 escalation, got %d", len(escList))
	}

	resp := escList[0]

	// Verify hidden groups are removed
	for _, group := range resp.Spec.Approvers.Groups {
		if group == "flm-on-duty" || group == "on-call" {
			t.Fatalf("hidden group should be removed from response: %s", group)
		}
	}

	// Verify visible group is present
	if len(resp.Spec.Approvers.Groups) != 1 || resp.Spec.Approvers.Groups[0] != "security-team" {
		t.Fatalf("expected only visible group 'security-team', got: %v", resp.Spec.Approvers.Groups)
	}

	// Verify HiddenFromUI field is removed from response
	if len(resp.Spec.Approvers.HiddenFromUI) > 0 {
		t.Fatalf("HiddenFromUI field should be removed from response, got: %v", resp.Spec.Approvers.HiddenFromUI)
	}
}
