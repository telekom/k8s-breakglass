package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"github.com/telekom/k8s-breakglass/pkg/ratelimit"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestWebhookRateLimiting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	setupWebhookController := func(t *testing.T) *WebhookController {
		builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
		for k, fn := range sessionIndexFnsWebhook {
			builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
		}
		cli := builder.Build()

		sesMgr := &breakglass.SessionManager{Client: cli}
		escalMgr := &escalation.EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

		// Always allow RBAC for these tests
		wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
			return true, nil
		}

		return wc
	}

	makeSARRequest := func(engine *gin.Engine, remoteAddr string) *httptest.ResponseRecorder {
		sar := authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: "alice@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Resource:  "pods",
				},
			},
		}
		body, _ := json.Marshal(sar)

		req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w
	}

	t.Run("webhook controller initializes with rate limiter", func(t *testing.T) {
		wc := setupWebhookController(t)
		require.NotNil(t, wc.rateLimiter, "rate limiter should be initialized")

		// Check it uses SAR config (high limits)
		cfg := wc.rateLimiter.Config()
		assert.Equal(t, float64(1000), cfg.Rate)
		assert.Equal(t, 5000, cfg.Burst)
	})

	t.Run("Handlers returns rate limiting middleware", func(t *testing.T) {
		wc := setupWebhookController(t)
		handlers := wc.Handlers()
		assert.Len(t, handlers, 1, "should return one handler (rate limiter)")
	})

	t.Run("allows high volume of SAR requests", func(t *testing.T) {
		wc := setupWebhookController(t)

		engine := gin.New()
		// Apply handlers (including rate limiter) to the group
		rg := engine.Group("/" + wc.BasePath())
		for _, h := range wc.Handlers() {
			rg.Use(h)
		}
		_ = wc.Register(rg)

		// Make many requests - should all succeed due to high SAR limits
		successCount := 0
		for i := 0; i < 1000; i++ {
			w := makeSARRequest(engine, "10.0.0.1:12345")
			if w.Code == http.StatusOK {
				successCount++
			}
		}

		// All requests should succeed within burst limit
		assert.Equal(t, 1000, successCount, "all 1000 requests should succeed")
	})

	t.Run("different IPs have separate rate limits", func(t *testing.T) {
		wc := setupWebhookController(t)

		engine := gin.New()
		rg := engine.Group("/" + wc.BasePath())
		for _, h := range wc.Handlers() {
			rg.Use(h)
		}
		_ = wc.Register(rg)

		// Make requests from IP1
		for i := 0; i < 100; i++ {
			makeSARRequest(engine, "10.0.0.1:12345")
		}

		// IP2 should still be able to make requests
		w := makeSARRequest(engine, "10.0.0.2:12345")
		assert.Equal(t, http.StatusOK, w.Code, "IP2 should not be affected by IP1's usage")
	})

	t.Run("rate limit eventually kicks in for excessive traffic", func(t *testing.T) {
		// Create controller with a very low rate limit for deterministic testing
		// Using default SAR config (1000 req/s, burst 5000) is too high and timing-dependent
		builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
		for k, fn := range sessionIndexFnsWebhook {
			builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
		}
		cli := builder.Build()

		sesMgr := &breakglass.SessionManager{Client: cli}
		escalMgr := &escalation.EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()

		// Create controller with custom low-limit rate limiter for testing
		// Use very low burst (10) so we can reliably exceed it with 50 requests
		testRateLimiter := ratelimit.New(ratelimit.Config{
			Rate:            1,  // 1 req/s (very slow refill)
			Burst:           10, // Small burst that we can easily exceed
			CleanupInterval: time.Minute,
			MaxAge:          time.Minute,
		})

		wc := &WebhookController{
			log:          logger.Sugar(),
			config:       config.Config{},
			sesManager:   sesMgr,
			escalManager: escalMgr,
			canDoFn: func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
				return true, nil
			},
			rateLimiter: testRateLimiter,
			denyEval:    policy.NewEvaluator(cli, logger.Sugar()),
		}

		engine := gin.New()
		rg := engine.Group("/" + wc.BasePath())
		for _, h := range wc.Handlers() {
			rg.Use(h)
		}
		_ = wc.Register(rg)

		// Make enough requests to exceed burst (10) - 50 should be plenty
		rateLimitedCount := 0
		for i := 0; i < 50; i++ {
			w := makeSARRequest(engine, "10.0.0.1:12345")
			if w.Code == http.StatusTooManyRequests {
				rateLimitedCount++
			}
		}

		// Should have some rate limited requests (at least 50 - 10 = 40)
		assert.Greater(t, rateLimitedCount, 0, "should have some rate limited requests after exceeding burst")
		// With burst of 10 and 50 requests, we should have ~40 rate limited
		assert.GreaterOrEqual(t, rateLimitedCount, 30, "should have at least 30 rate limited requests")
	})
}

func TestWebhookRateLimiterConfig(t *testing.T) {
	t.Run("SAR config is appropriate for high-volume webhook", func(t *testing.T) {
		cfg := ratelimit.DefaultSARConfig()

		// SAR needs to handle very high volume from K8s API servers
		assert.GreaterOrEqual(t, cfg.Rate, float64(1000), "SAR should allow at least 1000 req/s")
		assert.GreaterOrEqual(t, cfg.Burst, 5000, "SAR should allow burst of at least 5000")
	})

	t.Run("API config is more restrictive than SAR config", func(t *testing.T) {
		apiCfg := ratelimit.DefaultAPIConfig()
		sarCfg := ratelimit.DefaultSARConfig()

		assert.Less(t, apiCfg.Rate, sarCfg.Rate, "API rate should be lower than SAR rate")
		assert.Less(t, apiCfg.Burst, sarCfg.Burst, "API burst should be lower than SAR burst")
	})
}

func TestWebhookControllerWithNilRateLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create controller manually without rate limiter to test nil handling
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range sessionIndexFnsWebhook {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	wc := &WebhookController{
		log:          logger.Sugar(),
		config:       config.Config{},
		sesManager:   sesMgr,
		escalManager: escalMgr,
		canDoFn:      breakglass.CanGroupsDo,
		rateLimiter:  nil, // Explicitly nil
	}

	t.Run("Handlers returns empty slice when rate limiter is nil", func(t *testing.T) {
		handlers := wc.Handlers()
		assert.Len(t, handlers, 0, "should return empty handlers when rate limiter is nil")
	})
}

// Benchmark to verify rate limiter doesn't add significant overhead
func BenchmarkWebhookWithRateLimiter(b *testing.B) {
	gin.SetMode(gin.TestMode)

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	indexFns := map[string]client.IndexerFunc{
		"spec.user": func(o client.Object) []string {
			return []string{o.(*breakglassv1alpha1.BreakglassSession).Spec.User}
		},
		"spec.cluster": func(o client.Object) []string {
			return []string{o.(*breakglassv1alpha1.BreakglassSession).Spec.Cluster}
		},
	}
	for k, fn := range indexFns {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
		return true, nil
	}

	engine := gin.New()
	rg := engine.Group("/" + wc.BasePath())
	for _, h := range wc.Handlers() {
		rg.Use(h)
	}
	_ = wc.Register(rg)

	sar := authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "alice@example.com",
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}
	body, _ := json.Marshal(sar)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
	}
}
