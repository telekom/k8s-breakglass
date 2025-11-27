package breakglass

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// TestHandleGetEscalations_ReturnsEscalationsForTokenGroups
//
// Purpose:
//
//	Confirms the BreakglassEscalationController HTTP handler returns only the
//	escalations visible to the token groups injected into the context by
//	middleware.
//
// Reasoning:
//
//	The handler depends on caller identity and group membership to filter
//	escalations. This test ensures the middleware+handler integration yields
//	the expected filtered results.
//
// Flow pattern:
//   - Seed fake client with two escalations (one matching 'system:authenticated').
//   - Provide middleware that sets the request groups.
//   - Call GET and assert only the matching escalation is returned.
func TestHandleGetEscalations_ReturnsEscalationsForTokenGroups(t *testing.T) {
	// Build a fake client with two escalations, one matching system:authenticated
	esc1 := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-auth", Namespace: "default"},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed:        telekomv1alpha1.BreakglassEscalationAllowed{Groups: []string{"system:authenticated"}},
			EscalatedGroup: "escalated-1",
		},
	}
	esc2 := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-other", Namespace: "default"},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed:        telekomv1alpha1.BreakglassEscalationAllowed{Groups: []string{"other-group"}},
			EscalatedGroup: "escalated-2",
		},
	}

	cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(esc1, esc2).Build()
	em := EscalationManager{Client: cli}

	logger := zap.NewNop().Sugar()

	// middleware to inject token-derived email and groups into gin context
	middleware := func(c *gin.Context) {
		c.Set("email", "user@example.com")
		c.Set("groups", []string{"system:authenticated"})
		c.Next()
	}

	controller := &BreakglassEscalationController{
		manager:          &em,
		log:              logger,
		middleware:       middleware,
		identityProvider: KeycloakIdentityProvider{},
	}

	engine := gin.New()
	// Register controller with its middleware so the test middleware runs for the route
	_ = controller.Register(engine.Group("/"+controller.BasePath(), controller.Handlers()...))

	req := httptest.NewRequest(http.MethodGet, "/breakglassEscalations", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Result().StatusCode)
	}

	var out []telekomv1alpha1.BreakglassEscalation
	if err := json.NewDecoder(w.Result().Body).Decode(&out); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Only esc1 should be returned because the token groups include system:authenticated
	if len(out) != 1 {
		t.Fatalf("expected 1 escalation in response, got %d", len(out))
	}
	if out[0].Name != "esc-auth" {
		t.Fatalf("expected esc-auth, got %s", out[0].Name)
	}
}
