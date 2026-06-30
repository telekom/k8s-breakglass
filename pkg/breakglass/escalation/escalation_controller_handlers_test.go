package escalation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func decodeEscalationListEnvelope(t *testing.T, w *httptest.ResponseRecorder) []breakglassv1alpha1.BreakglassEscalation {
	t.Helper()
	var envelope struct {
		Items []breakglassv1alpha1.BreakglassEscalation `json:"items"`
		Total int                                        `json:"total"`
	}
	if err := json.NewDecoder(w.Result().Body).Decode(&envelope); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	return envelope.Items
}

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
	esc1 := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-auth", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed:        breakglassv1alpha1.BreakglassEscalationAllowed{Groups: []string{"system:authenticated"}},
			EscalatedGroup: "escalated-1",
		},
	}
	esc2 := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-other", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed:        breakglassv1alpha1.BreakglassEscalationAllowed{Groups: []string{"other-group"}},
			EscalatedGroup: "escalated-2",
		},
	}

	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(esc1, esc2).Build()
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
		identityProvider: breakglass.NewKeycloakIdentityProvider(nil),
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

	out := decodeEscalationListEnvelope(t, w)

	// Only esc1 should be returned because the token groups include system:authenticated
	if len(out) != 1 {
		t.Fatalf("expected 1 escalation in response, got %d", len(out))
	}
	if out[0].Name != "esc-auth" {
		t.Fatalf("expected esc-auth, got %s", out[0].Name)
	}
}

func TestHandleGetEscalations_HidesEscalationsForUnreadyClusterConfig(t *testing.T) {
	readyEsc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-ready", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"ready-cluster"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "ready-group",
		},
	}
	unreadyEsc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-unready", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"unready-cluster"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "unready-group",
		},
	}
	readyCluster := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ready-cluster", Namespace: "default"},
		Status: breakglassv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{{
				Type:   string(breakglassv1alpha1.ClusterConfigConditionReady),
				Status: metav1.ConditionTrue,
			}},
		},
	}
	unreadyCluster := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "unready-cluster", Namespace: "default"},
		Status: breakglassv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{{
				Type:   string(breakglassv1alpha1.ClusterConfigConditionReady),
				Status: metav1.ConditionFalse,
			}},
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(breakglass.Scheme).
		WithObjects(readyEsc, unreadyEsc, readyCluster, unreadyCluster).
		Build()
	em := EscalationManager{Client: cli}

	controller := &BreakglassEscalationController{
		manager:          &em,
		log:              zap.NewNop().Sugar(),
		middleware:       func(c *gin.Context) { c.Next() },
		identityProvider: &stubIdentityProvider{email: "user@example.com"},
	}

	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		c.Set("groups", []string{"system:authenticated"})
		c.Next()
	})
	_ = controller.Register(engine.Group("/" + controller.BasePath()))

	req := httptest.NewRequest(http.MethodGet, "/breakglassEscalations", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Result().StatusCode)
	}

	out := decodeEscalationListEnvelope(t, w)
	if len(out) != 1 {
		t.Fatalf("expected only ready escalation, got %#v", out)
	}
	if out[0].Name != "esc-ready" {
		t.Fatalf("expected esc-ready, got %s", out[0].Name)
	}
}

func TestHandleGetEscalations_ClusterFilterGlobUsesClusterConfigReadiness(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-prod", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"prod-*"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "prod-group",
		},
	}

	tests := []struct {
		name           string
		clusterConfigs []client.Object
		wantCount      int
	}{
		{
			name: "hides escalation when all matching ClusterConfigs are unready",
			clusterConfigs: []client.Object{
				clusterConfigWithReadyCondition("prod-a", "default", metav1.ConditionFalse),
				clusterConfigWithReadyCondition("prod-b", "default", metav1.ConditionFalse),
			},
			wantCount: 0,
		},
		{
			name: "keeps escalation when a matching ClusterConfig is ready",
			clusterConfigs: []client.Object{
				clusterConfigWithReadyCondition("prod-a", "default", metav1.ConditionFalse),
				clusterConfigWithReadyCondition("prod-b", "default", metav1.ConditionTrue),
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects := []client.Object{esc.DeepCopy()}
			objects = append(objects, tt.clusterConfigs...)
			cli := fake.NewClientBuilder().
				WithScheme(breakglass.Scheme).
				WithObjects(objects...).
				Build()
			em := EscalationManager{Client: cli}

			controller := &BreakglassEscalationController{
				manager:          &em,
				log:              zap.NewNop().Sugar(),
				middleware:       func(c *gin.Context) { c.Next() },
				identityProvider: &stubIdentityProvider{email: "user@example.com"},
			}

			engine := gin.New()
			engine.Use(func(c *gin.Context) {
				c.Set("groups", []string{"system:authenticated"})
				c.Next()
			})
			_ = controller.Register(engine.Group("/" + controller.BasePath()))

			req := httptest.NewRequest(http.MethodGet, "/breakglassEscalations?cluster=prod-*", nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			if w.Result().StatusCode != http.StatusOK {
				t.Fatalf("expected 200 OK, got %d", w.Result().StatusCode)
			}

			out := decodeEscalationListEnvelope(t, w)
			if len(out) != tt.wantCount {
				t.Fatalf("expected %d escalations, got %#v", tt.wantCount, out)
			}
		})
	}
}

func TestHandleGetEscalations_HidesEscalationsForDuplicateClusterConfigNames(t *testing.T) {
	clusterName := "duplicate-cluster"
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-duplicate-cluster", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "duplicate-group",
		},
	}
	firstCluster := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: "first"},
		Status: breakglassv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{{
				Type:   string(breakglassv1alpha1.ClusterConfigConditionReady),
				Status: metav1.ConditionTrue,
			}},
		},
	}
	secondCluster := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: "second"},
		Status: breakglassv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{{
				Type:   string(breakglassv1alpha1.ClusterConfigConditionReady),
				Status: metav1.ConditionTrue,
			}},
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(breakglass.Scheme).
		WithObjects(esc, firstCluster, secondCluster).
		Build()
	em := EscalationManager{Client: cli}

	controller := &BreakglassEscalationController{
		manager:          &em,
		log:              zap.NewNop().Sugar(),
		middleware:       func(c *gin.Context) { c.Next() },
		identityProvider: &stubIdentityProvider{email: "user@example.com"},
	}

	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		c.Set("groups", []string{"system:authenticated"})
		c.Next()
	})
	_ = controller.Register(engine.Group("/" + controller.BasePath()))

	req := httptest.NewRequest(http.MethodGet, "/breakglassEscalations", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Result().StatusCode)
	}

	out := decodeEscalationListEnvelope(t, w)
	if len(out) != 0 {
		t.Fatalf("expected duplicate cluster config name to hide escalation, got %#v", out)
	}
}

func clusterConfigWithReadyCondition(name, namespace string, status metav1.ConditionStatus) client.Object {
	return &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Status: breakglassv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{{
				Type:   string(breakglassv1alpha1.ClusterConfigConditionReady),
				Status: status,
			}},
		},
	}
}
