package webhook

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
	authorizationv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/policy"
)

// newTestWebhookController creates a minimal WebhookController for helper tests.
func newTestWebhookController(t *testing.T) *WebhookController {
	t.Helper()
	logger := zaptest.NewLogger(t)
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}
	cfg := config.Config{}
	cfg.Frontend.BaseURL = "https://breakglass.example.com"
	return NewWebhookController(logger.Sugar(), cfg, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))
}

// newTestState creates a minimal authorizeState for unit tests.
func newTestState(t *testing.T) *authorizeState {
	t.Helper()
	logger := zaptest.NewLogger(t)
	return &authorizeState{
		startTime:   time.Now(),
		clusterName: "test-cluster",
		ctx:         context.Background(),
		reqLog:      logger.Sugar(),
		phases:      NewSARPhaseTracker("test-cluster", logger.Sugar()),
		sar: authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: "alice@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:     "get",
					Resource: "pods",
				},
			},
		},
	}
}

func TestBuildFinalReason_AllowedByRBAC(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.allowed = true
	s.allowSource = "rbac"
	s.allowDetail = "groups=[admin]"

	wc.buildFinalReason(s)

	assert.Contains(t, s.reason, "Allowed by RBAC (groups=[admin])")
}

func TestBuildFinalReason_AllowedBySession(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.allowed = true
	s.allowSource = "session"
	s.allowDetail = "group=admin session=my-session impersonated=admin"

	wc.buildFinalReason(s)

	assert.Contains(t, s.reason, "Allowed by breakglass session")
	assert.Contains(t, s.reason, "group=admin session=my-session")
}

func TestBuildFinalReason_AllowedPreservesExistingReason(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.allowed = true
	s.allowSource = "debug-session"
	s.reason = "Debug session authorized"

	wc.buildFinalReason(s)

	assert.Contains(t, s.reason, "Debug session authorized")
}

func TestBuildFinalReason_DeniedWithSessionSARSkip(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.allowed = false
	s.sessions = []breakglassv1alpha1.BreakglassSession{{
		Spec: breakglassv1alpha1.BreakglassSessionSpec{GrantedGroup: "admin"},
	}}
	s.sessions[0].Name = "session-1"
	s.sessionSARSkipErr = errors.New("rest config unavailable")

	wc.buildFinalReason(s)

	assert.Contains(t, s.reason, "1 active breakglass session(s) found")
	assert.Contains(t, s.reason, "session-1(admin)")
	assert.Contains(t, s.reason, "rest config unavailable")
}

func TestBuildFinalReason_DeniedWithIDPMismatch(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.allowed = false
	s.issuer = "https://idp-a.example.com"
	s.idpMismatches = []breakglassv1alpha1.BreakglassSession{{
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			IdentityProviderName: "idp-b",
		},
	}}

	wc.buildFinalReason(s)

	assert.Contains(t, s.reason, "from different identity provider")
	assert.Contains(t, s.reason, "idp-b")
}

func TestBuildFinalReason_DeniedWithBothSkipAndMismatch(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.allowed = false
	s.issuer = "https://idp-a.example.com"
	s.sessions = []breakglassv1alpha1.BreakglassSession{{
		Spec: breakglassv1alpha1.BreakglassSessionSpec{GrantedGroup: "dev"},
	}}
	s.sessions[0].Name = "ses-2"
	s.sessionSARSkipErr = errors.New("connectivity issue")
	s.idpMismatches = []breakglassv1alpha1.BreakglassSession{{
		Spec: breakglassv1alpha1.BreakglassSessionSpec{IdentityProviderName: "corp-idp"},
	}}

	wc.buildFinalReason(s)

	assert.Contains(t, s.reason, "active breakglass session(s)")
	assert.Contains(t, s.reason, "connectivity issue")
	assert.Contains(t, s.reason, "different identity provider")
	assert.Contains(t, s.reason, "corp-idp")
}

func TestBuildFinalReason_DeniedNoSessions(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.allowed = false

	wc.buildFinalReason(s)

	// Should have the finalized reason (breakglass link) but no session diagnostics
	assert.NotContains(t, s.reason, "active breakglass session(s)")
	assert.NotContains(t, s.reason, "different identity provider")
}

func TestBuildFinalReason_DeniedIDPMismatchNoNames(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.allowed = false
	s.issuer = "https://idp.example.com"
	// Mismatched sessions without IdentityProviderName set
	s.idpMismatches = []breakglassv1alpha1.BreakglassSession{{
		Spec: breakglassv1alpha1.BreakglassSessionSpec{},
	}}

	wc.buildFinalReason(s)

	// No IDP names → no mismatch diagnostic appended
	assert.NotContains(t, s.reason, "different identity provider")
}

func TestLogSARAction_ResourceAttributes(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
		Verb: "get", Group: "apps", Resource: "deployments", Namespace: "default",
	}

	// Should not panic, should set issuer to ""
	wc.logSARAction(s)
	assert.Empty(t, s.issuer)
}

func TestLogSARAction_NonResourceAttributes(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.sar.Spec.ResourceAttributes = nil
	s.sar.Spec.NonResourceAttributes = &authorizationv1.NonResourceAttributes{
		Path: "/healthz", Verb: "get",
	}

	wc.logSARAction(s)
	assert.Empty(t, s.issuer)
}

func TestLogSARAction_NoAttributes(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.sar.Spec.ResourceAttributes = nil
	s.sar.Spec.NonResourceAttributes = nil

	wc.logSARAction(s)
	assert.Empty(t, s.issuer)
}

func TestLogSARAction_IssuerExtraction(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.sar.Spec.Extra = map[string]authorizationv1.ExtraValue{
		"identity.t-caas.telekom.com/issuer": {"https://idp.example.com"},
	}

	wc.logSARAction(s)
	assert.Equal(t, "https://idp.example.com", s.issuer)
}

func TestLogSARAction_EmptyIssuerExtra(t *testing.T) {
	wc := newTestWebhookController(t)
	s := newTestState(t)
	s.sar.Spec.Extra = map[string]authorizationv1.ExtraValue{
		"some-other-key": {"value"},
	}

	wc.logSARAction(s)
	assert.Empty(t, s.issuer)
}
