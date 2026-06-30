package breakglass

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCheckSessionLimits_MissingIDP(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	wc := &BreakglassSessionController{
		sessionManager: &SessionManager{
			Client: fakeClient,
		},
	}

	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-esc"},
	}

	err := wc.checkSessionLimits(context.Background(), esc, "missing-idp", "test@example.com", []string{"developers"}, log)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IdentityProvider \"missing-idp\" not found")
}

func TestHandleGetBreakglassSessionStatus_ContextCancellation(t *testing.T) {
	// We want to test that handleGetBreakglassSessionStatus respects request context cancellation
	// To do this, we need to mock the SessionManager to verify the context it receives is canceled.
	// We can use a custom RoundTripper or just inject a timeout into the gin context.

	logger, _ := zap.NewDevelopment()
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()

	// We will create a background context and cancel it to simulate client disconnect
	reqCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, "/breakglassSessions", nil)

	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)

	// Create a dummy session manager
	// Wait, we need the actual controller
	sesmanager := SessionManager{Client: &cancelableClient{Client: cli}}
	escmanager := testEscalationLookup{Client: cli}

	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, func(c *gin.Context) {
		c.Set("email", "user@e.com")
		c.Next()
	}, "/config/config.yaml", nil, cli)

	engine.GET("/breakglassSessions", ctrl.handleGetBreakglassSessionStatus)

	engine.ServeHTTP(w, req)

	// Since the context was canceled, the Kubernetes client should return context.Canceled
	// which our handler should catch and return 499.
	if w.Result().StatusCode != 499 {
		t.Fatalf("expected 499 Client Closed Request on context cancellation, got %d", w.Result().StatusCode)
	}
}

type cancelableClient struct {
	client.Client
}

func (c *cancelableClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return c.Client.List(ctx, list, opts...)
}
