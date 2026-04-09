package webhook

import (
	"context"
	"testing"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/policy"
)

// newTestWebhookControllerWithIDPs creates a minimal WebhookController backed by a fake client
// pre-populated with the provided IdentityProvider objects.
func newTestWebhookControllerWithIDPs(t *testing.T, idps ...*breakglassv1alpha1.IdentityProvider) *WebhookController {
	t.Helper()

	objs := make([]client.Object, 0, len(idps))
	for _, idp := range idps {
		objs = append(objs, idp)
	}

	cli := fake.NewClientBuilder().
		WithScheme(breakglass.Scheme).
		WithObjects(objs...).
		Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	wc := NewWebhookController(
		logger.Sugar(),
		config.Config{},
		sesMgr,
		escalMgr,
		nil,
		policy.NewEvaluator(cli, logger.Sugar()),
	)
	return wc
}

// makeIDP is a convenience helper that builds a minimal IdentityProvider for tests.
func makeIDP(name, issuer string, disabled bool) *breakglassv1alpha1.IdentityProvider {
	return &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			Issuer:   issuer,
			Disabled: disabled,
		},
	}
}

// makeEscalWithForRequests returns a BreakglassEscalation whose
// AllowedIdentityProvidersForRequests is set to the given list.
func makeEscalWithForRequests(name string, allowedIDPs []string) *breakglassv1alpha1.BreakglassEscalation {
	return &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProvidersForRequests: allowedIDPs,
		},
	}
}

// TestIsRequestFromAllowedIDP_AllowWhenForRequestsEmpty verifies backward-compatibility:
// when an escalation has no AllowedIdentityProvidersForRequests restrictions the function
// must return true regardless of the issuer.
func TestIsRequestFromAllowedIDP_AllowWhenForRequestsEmpty(t *testing.T) {
	idp := makeIDP("keycloak", "https://keycloak.corp.com", false)
	wc := newTestWebhookControllerWithIDPs(t, idp)

	esc := makeEscalWithForRequests("esc-open", nil)
	logger, _ := zap.NewDevelopment()
	reqLog := logger.Sugar()

	got := wc.isRequestFromAllowedIDP(context.Background(), "https://keycloak.corp.com", esc, reqLog)
	if !got {
		t.Fatal("expected true when AllowedIdentityProvidersForRequests is empty, got false")
	}
}

// TestIsRequestFromAllowedIDP_AllowMatchingIDP verifies that a request whose issuer maps to
// an enabled IdentityProvider that is listed in AllowedIdentityProvidersForRequests is allowed.
func TestIsRequestFromAllowedIDP_AllowMatchingIDP(t *testing.T) {
	idp := makeIDP("keycloak", "https://keycloak.corp.com", false)
	wc := newTestWebhookControllerWithIDPs(t, idp)

	esc := makeEscalWithForRequests("esc-keycloak-only", []string{"keycloak"})
	logger, _ := zap.NewDevelopment()
	reqLog := logger.Sugar()

	got := wc.isRequestFromAllowedIDP(context.Background(), "https://keycloak.corp.com", esc, reqLog)
	if !got {
		t.Fatal("expected true when issuer matches enabled IDP in AllowedIdentityProvidersForRequests, got false")
	}
}

// TestIsRequestFromAllowedIDP_DenyWhenIssuerMissing verifies that a request without an issuer
// is denied when AllowedIdentityProvidersForRequests is non-empty (fail-closed).
func TestIsRequestFromAllowedIDP_DenyWhenIssuerMissing(t *testing.T) {
	idp := makeIDP("keycloak", "https://keycloak.corp.com", false)
	wc := newTestWebhookControllerWithIDPs(t, idp)

	esc := makeEscalWithForRequests("esc-keycloak-only", []string{"keycloak"})
	logger, _ := zap.NewDevelopment()
	reqLog := logger.Sugar()

	got := wc.isRequestFromAllowedIDP(context.Background(), "", esc, reqLog)
	if got {
		t.Fatal("expected false when issuer is empty and AllowedIdentityProvidersForRequests is non-empty, got true")
	}
}

// TestIsRequestFromAllowedIDP_DenyWhenIssuerNotMatchingAnyIDP verifies that a request whose
// issuer does not match any configured IdentityProvider is denied.
func TestIsRequestFromAllowedIDP_DenyWhenIssuerNotMatchingAnyIDP(t *testing.T) {
	idp := makeIDP("keycloak", "https://keycloak.corp.com", false)
	wc := newTestWebhookControllerWithIDPs(t, idp)

	esc := makeEscalWithForRequests("esc-keycloak-only", []string{"keycloak"})
	logger, _ := zap.NewDevelopment()
	reqLog := logger.Sugar()

	// issuer is a completely unknown provider
	got := wc.isRequestFromAllowedIDP(context.Background(), "https://unknown-idp.example.com", esc, reqLog)
	if got {
		t.Fatal("expected false when issuer does not match any IDP, got true")
	}
}

// TestIsRequestFromAllowedIDP_DenyWhenMatchedIDPIsDisabled verifies that even when the issuer
// matches a known IdentityProvider, the request is denied if that provider is disabled.
func TestIsRequestFromAllowedIDP_DenyWhenMatchedIDPIsDisabled(t *testing.T) {
	idp := makeIDP("keycloak", "https://keycloak.corp.com", true /* disabled */)
	wc := newTestWebhookControllerWithIDPs(t, idp)

	esc := makeEscalWithForRequests("esc-keycloak-only", []string{"keycloak"})
	logger, _ := zap.NewDevelopment()
	reqLog := logger.Sugar()

	got := wc.isRequestFromAllowedIDP(context.Background(), "https://keycloak.corp.com", esc, reqLog)
	if got {
		t.Fatal("expected false when matched IDP is disabled, got true")
	}
}

// TestIsRequestFromAllowedIDP_DenyWhenIDPNotInAllowedList verifies that a request whose issuer
// maps to an enabled IDP is denied when that IDP is NOT in AllowedIdentityProvidersForRequests.
func TestIsRequestFromAllowedIDP_DenyWhenIDPNotInAllowedList(t *testing.T) {
	keycloak := makeIDP("keycloak", "https://keycloak.corp.com", false)
	ldap := makeIDP("ldap", "https://ldap.corp.com", false)
	wc := newTestWebhookControllerWithIDPs(t, keycloak, ldap)

	// escalation only allows "ldap"
	esc := makeEscalWithForRequests("esc-ldap-only", []string{"ldap"})
	logger, _ := zap.NewDevelopment()
	reqLog := logger.Sugar()

	// request comes from keycloak issuer → should be denied
	got := wc.isRequestFromAllowedIDP(context.Background(), "https://keycloak.corp.com", esc, reqLog)
	if got {
		t.Fatal("expected false when IDP is enabled but not in AllowedIdentityProvidersForRequests, got true")
	}
}
