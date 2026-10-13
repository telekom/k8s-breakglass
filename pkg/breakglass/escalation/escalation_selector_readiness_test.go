package escalation

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEscalationSelectorReadiness(t *testing.T) {
	esc := breakglassv1alpha1.BreakglassEscalation{Spec: breakglassv1alpha1.BreakglassEscalationSpec{
		Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{Clusters: []string{"*"},
			ClusterSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"stage": "ref"}}},
	}}
	labels := map[string]map[string]string{"prd": {"stage": "prd"}, "ref": {"stage": "ref"}}
	require.False(t, escalationHasReadyCluster(esc, "", nil, labels))
	require.False(t, escalationHasReadyCluster(esc, "", map[string]bool{"prd": true, "ref": false}, labels))
	require.False(t, escalationHasReadyCluster(esc, "prd", map[string]bool{"prd": true, "ref": true}, labels))
	require.True(t, escalationHasReadyCluster(esc, "", map[string]bool{"prd": false, "ref": true}, labels))
	require.False(t, escalationHasReadyCluster(esc, "", map[string]bool{"ref": true}))
	esc.Spec.Allowed.ClusterSelector = &metav1.LabelSelector{}
	require.False(t, escalationHasReadyCluster(esc, "", map[string]bool{"ref": true}, labels))
	esc.Spec.Allowed.ClusterSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "stage", Operator: "invalid"}}}
	require.False(t, escalationHasReadyCluster(esc, "", map[string]bool{"ref": true}, labels))
}

func TestHandleGetEscalations_ClusterSelectorTargets(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-ops", Namespace: "hub"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{Clusters: []string{"*"}, Groups: []string{"ops"},
				ClusterSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"stage": "ref"}}},
			EscalatedGroup: "platform",
		},
	}
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(esc,
		&breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "ref", Namespace: "spokes", Labels: map[string]string{"stage": "ref"}}},
		&breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "prd", Namespace: "spokes", Labels: map[string]string{"stage": "prd"}}},
	).Build()
	controller := &BreakglassEscalationController{
		manager: &EscalationManager{Client: cli}, log: zap.NewNop().Sugar(),
		middleware: func(c *gin.Context) {
			c.Set("email", "ops@example.com")
			c.Set("groups", []string{"ops"})
			c.Next()
		},
		identityProvider: breakglass.NewKeycloakIdentityProvider(nil),
	}
	engine := gin.New()
	require.NoError(t, controller.Register(engine.Group("/"+controller.BasePath(), controller.Handlers()...)))
	for _, tc := range []struct {
		query string
		count int
	}{
		{"?activeOnly=false", 1},
		{"?activeOnly=false&cluster=ref", 1},
		{"?activeOnly=false&cluster=r*", 1},
		{"?activeOnly=false&cluster=prd", 0},
	} {
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/breakglassEscalations"+tc.query, nil))
		require.Equal(t, http.StatusOK, w.Code)
		items := decodeEscalationListEnvelope(t, w)
		require.Len(t, items, tc.count)
		if tc.count > 0 {
			require.Equal(t, []string{"ref"}, items[0].Spec.Allowed.Clusters)
		}
	}
	var stored breakglassv1alpha1.BreakglassEscalation
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(esc), &stored))
	require.Equal(t, []string{"*"}, stored.Spec.Allowed.Clusters, "discovery must not mutate stored policy")
}
