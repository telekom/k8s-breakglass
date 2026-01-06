package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSessionMetricsExistAndIncrement(t *testing.T) {
	// Use a test label to avoid colliding with other tests
	lbl := "test-cluster"

	// Ensure counters are present and can be incremented/read
	SessionCreated.WithLabelValues(lbl).Inc()
	if v := testutil.ToFloat64(SessionCreated.WithLabelValues(lbl)); v < 1 {
		t.Fatalf("expected SessionCreated >= 1, got %v", v)
	}

	SessionUpdated.WithLabelValues(lbl).Add(2)
	if v := testutil.ToFloat64(SessionUpdated.WithLabelValues(lbl)); v < 2 {
		t.Fatalf("expected SessionUpdated >= 2, got %v", v)
	}

	SessionDeleted.WithLabelValues(lbl).Inc()
	if v := testutil.ToFloat64(SessionDeleted.WithLabelValues(lbl)); v < 1 {
		t.Fatalf("expected SessionDeleted >= 1, got %v", v)
	}

	SessionExpired.WithLabelValues(lbl).Inc()
	if v := testutil.ToFloat64(SessionExpired.WithLabelValues(lbl)); v < 1 {
		t.Fatalf("expected SessionExpired >= 1, got %v", v)
	}
}

func TestEscalationIDPAuthorizationChecksLabelCardinality(t *testing.T) {
	EscalationIDPAuthorizationChecks.Reset()
	defer EscalationIDPAuthorizationChecks.Reset()
	labels := []string{"admin-group", "production-keycloak", "allowed"}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("EscalationIDPAuthorizationChecks panicked with labels %v: %v", labels, r)
		}
	}()

	EscalationIDPAuthorizationChecks.WithLabelValues(labels...).Inc()
	if v := testutil.ToFloat64(EscalationIDPAuthorizationChecks.WithLabelValues(labels...)); v != 1 {
		t.Fatalf("expected metric value 1 after increment, got %v", v)
	}
}

// TestDebugSessionMetrics verifies debug session metrics work correctly
func TestDebugSessionMetrics(t *testing.T) {
	cluster := "test-debug-cluster"
	template := "debug-template"

	t.Run("created counter", func(t *testing.T) {
		before := testutil.ToFloat64(DebugSessionsCreated.WithLabelValues(cluster, template))
		DebugSessionsCreated.WithLabelValues(cluster, template).Inc()
		after := testutil.ToFloat64(DebugSessionsCreated.WithLabelValues(cluster, template))
		if after != before+1 {
			t.Fatalf("expected DebugSessionsCreated to increment by 1, got %v -> %v", before, after)
		}
	})

	t.Run("active gauge", func(t *testing.T) {
		DebugSessionsActive.WithLabelValues(cluster, template).Set(5)
		if v := testutil.ToFloat64(DebugSessionsActive.WithLabelValues(cluster, template)); v != 5 {
			t.Fatalf("expected DebugSessionsActive = 5, got %v", v)
		}
		DebugSessionsActive.WithLabelValues(cluster, template).Dec()
		if v := testutil.ToFloat64(DebugSessionsActive.WithLabelValues(cluster, template)); v != 4 {
			t.Fatalf("expected DebugSessionsActive = 4 after decrement, got %v", v)
		}
	})

	t.Run("terminated counter", func(t *testing.T) {
		before := testutil.ToFloat64(DebugSessionsTerminated.WithLabelValues(cluster, "user_terminated"))
		DebugSessionsTerminated.WithLabelValues(cluster, "user_terminated").Inc()
		after := testutil.ToFloat64(DebugSessionsTerminated.WithLabelValues(cluster, "user_terminated"))
		if after != before+1 {
			t.Fatalf("expected DebugSessionsTerminated to increment by 1")
		}
	})

	t.Run("expired counter", func(t *testing.T) {
		before := testutil.ToFloat64(DebugSessionsExpired.WithLabelValues(cluster, template))
		DebugSessionsExpired.WithLabelValues(cluster, template).Inc()
		after := testutil.ToFloat64(DebugSessionsExpired.WithLabelValues(cluster, template))
		if after != before+1 {
			t.Fatalf("expected DebugSessionsExpired to increment by 1")
		}
	})

	t.Run("participants gauge", func(t *testing.T) {
		sessionName := "test-session"
		DebugSessionParticipants.WithLabelValues(cluster, sessionName).Set(3)
		if v := testutil.ToFloat64(DebugSessionParticipants.WithLabelValues(cluster, sessionName)); v != 3 {
			t.Fatalf("expected DebugSessionParticipants = 3, got %v", v)
		}
	})

	t.Run("approval metrics", func(t *testing.T) {
		before := testutil.ToFloat64(DebugSessionApprovalRequired.WithLabelValues(cluster, template))
		DebugSessionApprovalRequired.WithLabelValues(cluster, template).Inc()
		after := testutil.ToFloat64(DebugSessionApprovalRequired.WithLabelValues(cluster, template))
		if after != before+1 {
			t.Fatalf("expected DebugSessionApprovalRequired to increment by 1")
		}

		before = testutil.ToFloat64(DebugSessionApproved.WithLabelValues(cluster, "user"))
		DebugSessionApproved.WithLabelValues(cluster, "user").Inc()
		after = testutil.ToFloat64(DebugSessionApproved.WithLabelValues(cluster, "user"))
		if after != before+1 {
			t.Fatalf("expected DebugSessionApproved to increment by 1")
		}

		before = testutil.ToFloat64(DebugSessionRejected.WithLabelValues(cluster, "policy_violation"))
		DebugSessionRejected.WithLabelValues(cluster, "policy_violation").Inc()
		after = testutil.ToFloat64(DebugSessionRejected.WithLabelValues(cluster, "policy_violation"))
		if after != before+1 {
			t.Fatalf("expected DebugSessionRejected to increment by 1")
		}
	})

	t.Run("duration histogram", func(t *testing.T) {
		// Record durations in seconds
		DebugSessionDuration.WithLabelValues(cluster, template).Observe(1800) // 30 min
		DebugSessionDuration.WithLabelValues(cluster, template).Observe(3600) // 1 hour
		DebugSessionDuration.WithLabelValues(cluster, template).Observe(7200) // 2 hours
		// Just verify no panic - histogram values are harder to test
	})
}

// TestIdentityProviderMetrics verifies IDP metrics work correctly
func TestIdentityProviderMetrics(t *testing.T) {
	t.Run("loaded counter", func(t *testing.T) {
		before := testutil.ToFloat64(IdentityProviderLoaded.WithLabelValues("oidc"))
		IdentityProviderLoaded.WithLabelValues("oidc").Inc()
		after := testutil.ToFloat64(IdentityProviderLoaded.WithLabelValues("oidc"))
		if after != before+1 {
			t.Fatalf("expected IdentityProviderLoaded to increment")
		}
	})

	t.Run("conversion errors counter", func(t *testing.T) {
		before := testutil.ToFloat64(IdentityProviderConversionErrors.WithLabelValues("test-idp", "parse_error"))
		IdentityProviderConversionErrors.WithLabelValues("test-idp", "parse_error").Inc()
		after := testutil.ToFloat64(IdentityProviderConversionErrors.WithLabelValues("test-idp", "parse_error"))
		if after != before+1 {
			t.Fatalf("expected IdentityProviderConversionErrors to increment")
		}
	})

	t.Run("status gauge", func(t *testing.T) {
		IdentityProviderStatus.WithLabelValues("prod-keycloak", "keycloak").Set(1)
		if v := testutil.ToFloat64(IdentityProviderStatus.WithLabelValues("prod-keycloak", "keycloak")); v != 1 {
			t.Fatalf("expected IdentityProviderStatus = 1, got %v", v)
		}
	})
}

// TestWebhookMetrics verifies webhook-related metrics
func TestWebhookMetrics(t *testing.T) {
	cluster := "test-webhook-cluster"

	t.Run("SAR requests counter", func(t *testing.T) {
		before := testutil.ToFloat64(WebhookSARRequests.WithLabelValues(cluster))
		WebhookSARRequests.WithLabelValues(cluster).Inc()
		after := testutil.ToFloat64(WebhookSARRequests.WithLabelValues(cluster))
		if after != before+1 {
			t.Fatalf("expected WebhookSARRequests to increment")
		}
	})

	t.Run("SAR allowed counter", func(t *testing.T) {
		before := testutil.ToFloat64(WebhookSARAllowed.WithLabelValues(cluster))
		WebhookSARAllowed.WithLabelValues(cluster).Inc()
		after := testutil.ToFloat64(WebhookSARAllowed.WithLabelValues(cluster))
		if after != before+1 {
			t.Fatalf("expected WebhookSARAllowed to increment")
		}
	})

	t.Run("SAR denied counter", func(t *testing.T) {
		before := testutil.ToFloat64(WebhookSARDenied.WithLabelValues(cluster))
		WebhookSARDenied.WithLabelValues(cluster).Inc()
		after := testutil.ToFloat64(WebhookSARDenied.WithLabelValues(cluster))
		if after != before+1 {
			t.Fatalf("expected WebhookSARDenied to increment")
		}
	})

	t.Run("SAR decisions by action", func(t *testing.T) {
		labels := []string{cluster, "get", "core", "pods", "default", "", "allowed", ""}
		before := testutil.ToFloat64(WebhookSARDecisionsByAction.WithLabelValues(labels...))
		WebhookSARDecisionsByAction.WithLabelValues(labels...).Inc()
		after := testutil.ToFloat64(WebhookSARDecisionsByAction.WithLabelValues(labels...))
		if after != before+1 {
			t.Fatalf("expected WebhookSARDecisionsByAction to increment")
		}
	})
}

// TestMailMetrics verifies mail-related metrics
func TestMailMetrics(t *testing.T) {
	host := "smtp.test.com"

	t.Run("send success", func(t *testing.T) {
		before := testutil.ToFloat64(MailSendSuccess.WithLabelValues(host))
		MailSendSuccess.WithLabelValues(host).Inc()
		after := testutil.ToFloat64(MailSendSuccess.WithLabelValues(host))
		if after != before+1 {
			t.Fatalf("expected MailSendSuccess to increment")
		}
	})

	t.Run("send failure", func(t *testing.T) {
		before := testutil.ToFloat64(MailSendFailure.WithLabelValues(host))
		MailSendFailure.WithLabelValues(host).Inc()
		after := testutil.ToFloat64(MailSendFailure.WithLabelValues(host))
		if after != before+1 {
			t.Fatalf("expected MailSendFailure to increment")
		}
	})

	t.Run("queue metrics", func(t *testing.T) {
		before := testutil.ToFloat64(MailQueued.WithLabelValues(host))
		MailQueued.WithLabelValues(host).Inc()
		after := testutil.ToFloat64(MailQueued.WithLabelValues(host))
		if after != before+1 {
			t.Fatalf("expected MailQueued to increment")
		}
	})
}

// TestAPIMetrics verifies API endpoint metrics
func TestAPIMetrics(t *testing.T) {
	endpoint := "/api/v1/sessions"

	t.Run("requests counter", func(t *testing.T) {
		before := testutil.ToFloat64(APIEndpointRequests.WithLabelValues(endpoint))
		APIEndpointRequests.WithLabelValues(endpoint).Inc()
		after := testutil.ToFloat64(APIEndpointRequests.WithLabelValues(endpoint))
		if after != before+1 {
			t.Fatalf("expected APIEndpointRequests to increment")
		}
	})

	t.Run("errors counter", func(t *testing.T) {
		before := testutil.ToFloat64(APIEndpointErrors.WithLabelValues(endpoint, "500"))
		APIEndpointErrors.WithLabelValues(endpoint, "500").Inc()
		after := testutil.ToFloat64(APIEndpointErrors.WithLabelValues(endpoint, "500"))
		if after != before+1 {
			t.Fatalf("expected APIEndpointErrors to increment")
		}
	})

	t.Run("duration histogram", func(t *testing.T) {
		// Observe request durations
		APIEndpointDuration.WithLabelValues(endpoint).Observe(0.05)
		APIEndpointDuration.WithLabelValues(endpoint).Observe(0.1)
		// Just verify no panic
	})
}

// TestJWTMetrics verifies JWT validation metrics
func TestJWTMetrics(t *testing.T) {
	issuer := "https://keycloak.test/realms/test"

	t.Run("validation requests", func(t *testing.T) {
		before := testutil.ToFloat64(JWTValidationRequests.WithLabelValues(issuer, "multi-idp"))
		JWTValidationRequests.WithLabelValues(issuer, "multi-idp").Inc()
		after := testutil.ToFloat64(JWTValidationRequests.WithLabelValues(issuer, "multi-idp"))
		if after != before+1 {
			t.Fatalf("expected JWTValidationRequests to increment")
		}
	})

	t.Run("validation success", func(t *testing.T) {
		before := testutil.ToFloat64(JWTValidationSuccess.WithLabelValues(issuer))
		JWTValidationSuccess.WithLabelValues(issuer).Inc()
		after := testutil.ToFloat64(JWTValidationSuccess.WithLabelValues(issuer))
		if after != before+1 {
			t.Fatalf("expected JWTValidationSuccess to increment")
		}
	})

	t.Run("validation failure", func(t *testing.T) {
		before := testutil.ToFloat64(JWTValidationFailure.WithLabelValues(issuer, "expired"))
		JWTValidationFailure.WithLabelValues(issuer, "expired").Inc()
		after := testutil.ToFloat64(JWTValidationFailure.WithLabelValues(issuer, "expired"))
		if after != before+1 {
			t.Fatalf("expected JWTValidationFailure to increment")
		}
	})
}

// TestMetricsHandler verifies the metrics HTTP handler works
func TestMetricsHandler(t *testing.T) {
	handler := MetricsHandler()
	if handler == nil {
		t.Fatal("expected MetricsHandler to return non-nil handler")
	}
}
