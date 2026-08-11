package breakglass

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestSessionController(t *testing.T) *BreakglassSessionController {
	t.Helper()
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesManager := &SessionManager{Client: cli}
	escManager := &testEscalationLookup{Client: cli}
	logger := zaptest.NewLogger(t)
	return NewBreakglassSessionController(
		logger.Sugar(), config.Config{},
		sesManager, escManager,
		nil, "/config/config.yaml", nil, cli,
	)
}

// ----- collectApproversFromEscalations tests -----

func TestCollectApproversFromEscalations_EmptyList(t *testing.T) {
	wc := newTestSessionController(t)
	log := zaptest.NewLogger(t).Sugar()

	result := wc.collectApproversFromEscalations(context.Background(), nil, "admin", log)

	assert.NotNil(t, result)
	assert.Empty(t, result.possibleGroups)
	assert.Empty(t, result.allApprovers)
	assert.Nil(t, result.matchedEscalation)
	assert.Empty(t, result.selectedDenyPolicies)
}

func TestCollectApproversFromEscalations_FindsMatch(t *testing.T) {
	wc := newTestSessionController(t)
	log := zaptest.NewLogger(t).Sugar()

	escals := []breakglassv1alpha1.BreakglassEscalation{
		{
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "viewer",
				Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"bob@example.com"},
				},
			},
		},
		{
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "admin",
				Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"alice@example.com"},
				},
				DenyPolicyRefs: []string{"deny-destructive"},
			},
		},
	}

	result := wc.collectApproversFromEscalations(context.Background(), escals, "admin", log)

	assert.Contains(t, result.possibleGroups, "viewer")
	assert.Contains(t, result.possibleGroups, "admin")
	require.NotNil(t, result.matchedEscalation)
	assert.Equal(t, "admin", result.matchedEscalation.Spec.EscalatedGroup)
	assert.Contains(t, result.allApprovers, "bob@example.com")
	assert.Contains(t, result.allApprovers, "alice@example.com")
	assert.Equal(t, []string{"deny-destructive"}, result.selectedDenyPolicies)
}

func TestCollectApproversFromEscalations_NoMatch(t *testing.T) {
	wc := newTestSessionController(t)
	log := zaptest.NewLogger(t).Sugar()

	escals := []breakglassv1alpha1.BreakglassEscalation{
		{
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "viewer",
				Approvers:      breakglassv1alpha1.BreakglassEscalationApprovers{},
			},
		},
	}

	result := wc.collectApproversFromEscalations(context.Background(), escals, "admin", log)

	assert.Contains(t, result.possibleGroups, "viewer")
	assert.Nil(t, result.matchedEscalation)
}

func TestCollectApproversFromEscalations_DeduplicatesApprovers(t *testing.T) {
	wc := newTestSessionController(t)
	log := zaptest.NewLogger(t).Sugar()

	escals := []breakglassv1alpha1.BreakglassEscalation{
		{
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "admin",
				Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"alice@example.com", "bob@example.com"},
				},
			},
		},
		{
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "viewer",
				Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"alice@example.com", "charlie@example.com"},
				},
			},
		},
	}

	result := wc.collectApproversFromEscalations(context.Background(), escals, "admin", log)

	// alice appears in both escalations but should only appear once in allApprovers
	count := 0
	for _, a := range result.allApprovers {
		if a == "alice@example.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "alice should appear exactly once (deduplication)")
	assert.Contains(t, result.allApprovers, "bob@example.com")
	assert.Contains(t, result.allApprovers, "charlie@example.com")
}

// ----- escalationResolutionResult tests -----

func TestEscalationResolutionResult_Defaults(t *testing.T) {
	result := &escalationResolutionResult{
		possibleGroups:   []string{},
		approversByGroup: map[string][]string{},
	}
	assert.Empty(t, result.possibleGroups)
	assert.Empty(t, result.approversByGroup)
	assert.Nil(t, result.matchedEscalation)
	assert.Empty(t, result.selectedDenyPolicies)
}

// ----- sessionCreateParams tests -----

func TestSessionCreateParams_Fields(t *testing.T) {
	params := sessionCreateParams{
		spec: breakglassv1alpha1.BreakglassSessionSpec{
			GrantedGroup: "admin",
		},
		request: BreakglassSessionRequest{
			Clustername: "prod",
			GroupName:   "admin",
			Username:    "alice@example.com",
		},
		userIdentifier: "alice@example.com",
		userGroups:     []string{"team-a"},
		username:       "alice",
	}

	assert.Equal(t, "admin", params.spec.GrantedGroup)
	assert.Equal(t, "prod", params.request.Clustername)
	assert.Equal(t, "alice@example.com", params.userIdentifier)
	assert.Equal(t, []string{"team-a"}, params.userGroups)
	assert.Equal(t, "alice", params.username)
}

// ----- authenticatedIdentity tests -----

func TestAuthenticatedIdentity_Fields(t *testing.T) {
	id := authenticatedIdentity{
		email:    "alice@example.com",
		username: "alice",
	}
	assert.Equal(t, "alice@example.com", id.email)
	assert.Equal(t, "alice", id.username)
	assert.Nil(t, id.emailErr)
}

func TestAuthenticatedIdentity_WithError(t *testing.T) {
	id := authenticatedIdentity{
		emailErr: assert.AnError,
	}
	assert.Empty(t, id.email)
	assert.NotNil(t, id.emailErr)
}

// ----- buildSessionSpec integration tests -----

func TestBuildSessionSpec_AllowIDPMismatch_WithForRequestsOnly(t *testing.T) {
	wc := newTestSessionController(t)
	log := zaptest.NewLogger(t).Sugar()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("identity_provider_name", "requester-idp")
	c.Set("issuer", "https://idp.example.com")

	// Escalation uses only the new per-role field (legacy AllowedIdentityProviders is empty)
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-split", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:                       "admin",
			MaxValidFor:                          "1h",
			AllowedIdentityProvidersForRequests:  []string{"requester-idp"},
			AllowedIdentityProvidersForApprovers: []string{"approver-idp"},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Users: []string{"approver@example.com"},
			},
		},
	}

	request := BreakglassSessionRequest{
		Clustername: "test-cluster",
		GroupName:   "admin",
		Username:    "user@example.com",
	}

	spec, ok := wc.buildSessionSpec(c, request, "user@example.com", escalation, nil, nil, log)

	require.True(t, ok, "buildSessionSpec should succeed")
	assert.False(t, spec.AllowIDPMismatch,
		"AllowIDPMismatch must be false when AllowedIdentityProvidersForRequests restricts IDPs")
	assert.Equal(t, "requester-idp", spec.IdentityProviderName)
}

func TestBuildSessionSpec_AllowIDPMismatch_WithLegacyFieldOnly(t *testing.T) {
	wc := newTestSessionController(t)
	log := zaptest.NewLogger(t).Sugar()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("identity_provider_name", "corp-idp")
	c.Set("issuer", "https://corp.example.com")

	// Escalation uses legacy unified field only
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-legacy", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:           "admin",
			MaxValidFor:              "1h",
			AllowedIdentityProviders: []string{"corp-idp"},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Users: []string{"approver@example.com"},
			},
		},
	}

	request := BreakglassSessionRequest{
		Clustername: "test-cluster",
		GroupName:   "admin",
		Username:    "user@example.com",
	}

	spec, ok := wc.buildSessionSpec(c, request, "user@example.com", escalation, nil, nil, log)

	require.True(t, ok, "buildSessionSpec should succeed")
	assert.False(t, spec.AllowIDPMismatch,
		"AllowIDPMismatch must be false when legacy AllowedIdentityProviders restricts IDPs")
}

func TestBuildSessionSpec_AllowIDPMismatch_NeitherFieldSet(t *testing.T) {
	wc := newTestSessionController(t)
	log := zaptest.NewLogger(t).Sugar()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("identity_provider_name", "any-idp")
	c.Set("issuer", "https://any.example.com")

	// Escalation has no IDP restrictions at all
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-unrestricted", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "admin",
			MaxValidFor:    "1h",
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Users: []string{"approver@example.com"},
			},
		},
	}

	request := BreakglassSessionRequest{
		Clustername: "test-cluster",
		GroupName:   "admin",
		Username:    "user@example.com",
	}

	spec, ok := wc.buildSessionSpec(c, request, "user@example.com", escalation, nil, nil, log)

	require.True(t, ok, "buildSessionSpec should succeed")
	assert.True(t, spec.AllowIDPMismatch,
		"AllowIDPMismatch must be true when neither escalation nor cluster restricts IDPs (backward compat)")
}

func TestBuildSessionSpec_AllowIDPMismatch_ClusterRestrictionOverrides(t *testing.T) {
	wc := newTestSessionController(t)
	log := zaptest.NewLogger(t).Sugar()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("identity_provider_name", "any-idp")
	c.Set("issuer", "https://any.example.com")

	// Escalation is unrestricted but cluster has IDP refs
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-unrestricted", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "admin",
			MaxValidFor:    "1h",
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Users: []string{"approver@example.com"},
			},
		},
	}

	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			IdentityProviderRefs: []string{"idp-ref-1"},
		},
	}

	request := BreakglassSessionRequest{
		Clustername: "test-cluster",
		GroupName:   "admin",
		Username:    "user@example.com",
	}

	spec, ok := wc.buildSessionSpec(c, request, "user@example.com", escalation, clusterConfig, nil, log)

	require.True(t, ok, "buildSessionSpec should succeed")
	assert.False(t, spec.AllowIDPMismatch,
		"AllowIDPMismatch must be false when cluster has IDP restrictions even if escalation is unrestricted")
}

func TestResolveUserGroupsRedactsRawTokenGroupsWhenEnabled(t *testing.T) {
	system.SetLogRedaction(true)
	defer system.SetLogRedaction(false)

	gin.SetMode(gin.TestMode)

	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	sesManager := &SessionManager{Client: cli}
	escManager := &testEscalationLookup{Client: cli}

	core, recorded := observer.New(zap.DebugLevel)
	obsLogger := zap.New(core).Sugar()

	wc := NewBreakglassSessionController(
		zaptest.NewLogger(t).Sugar(), config.Config{},
		sesManager, escManager,
		nil, "/config/config.yaml", nil, cli,
	)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Set("groups", []string{"secret-admin-role", "internal-platform-ops", "privileged-cluster-access"})

	cug := ClusterUserGroup{Username: "alice@example.com", Clustername: "prod"}
	groups, ok := wc.resolveUserGroups(ctx, context.Background(), cug, nil, obsLogger)

	require.True(t, ok, "resolveUserGroups should succeed when groups are in context")
	require.ElementsMatch(t, []string{"secret-admin-role", "internal-platform-ops", "privileged-cluster-access"}, groups)

	for _, entry := range recorded.All() {
		fields := entry.ContextMap()
		if val, ok := fields["rawTokenGroups"]; ok {
			require.Equal(t, "[3 items]", val,
				"rawTokenGroups must be redacted when log redaction is enabled (found in: %q)", entry.Message)
		}
	}
}

// TestResolveUserGroupsRespectsEmptyTokenGroupsClaim ensures that when the JWT
// asserts the user belongs to zero groups (the "groups" context key is
// present but holds an empty slice, as set by the auth middleware for a
// present-but-empty groups/realm_access claim), resolveUserGroups does not
// fall back to cluster-based group resolution. Falling back in this case
// would silently replace the token's explicit "no groups" assertion with
// whatever groups the cluster happens to report for the user, which can
// grant unintended escalation access.
func TestResolveUserGroupsRespectsEmptyTokenGroupsClaim(t *testing.T) {
	gin.SetMode(gin.TestMode)

	wc := newTestSessionController(t)
	wc.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
		t.Fatal("cluster-based group lookup must not be called when the token asserts empty groups")
		return nil, nil
	}

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Set("groups", []string{}) // token carried a groups claim that resolved to zero groups

	cug := ClusterUserGroup{Username: "alice@example.com", Clustername: "prod"}
	groups, ok := wc.resolveUserGroups(ctx, context.Background(), cug, nil, zaptest.NewLogger(t).Sugar())

	require.True(t, ok, "resolveUserGroups should succeed when the token asserts empty groups")
	require.Empty(t, groups, "resolveUserGroups must respect the token's empty groups assertion")
}

// TestResolveUserGroupsFallsBackWhenNoTokenGroupsClaim ensures that
// resolveUserGroups still falls back to cluster-based group resolution when
// the token carries no group information at all (the "groups" context key is
// absent), preserving backward-compatible behavior for IDPs without a groups
// claim.
func TestResolveUserGroupsFallsBackWhenNoTokenGroupsClaim(t *testing.T) {
	gin.SetMode(gin.TestMode)

	wc := newTestSessionController(t)
	wc.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
		return []string{"cluster-admin"}, nil
	}

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	// No "groups" key set at all, simulating a token without a groups claim.

	cug := ClusterUserGroup{Username: "alice@example.com", Clustername: "prod"}
	groups, ok := wc.resolveUserGroups(ctx, context.Background(), cug, nil, zaptest.NewLogger(t).Sugar())

	require.True(t, ok)
	require.ElementsMatch(t, []string{"cluster-admin"}, groups)
}

// TestResolveUserGroupsFallbackPropagatesClusterLookupError ensures that when
// resolveUserGroups falls back to cluster-based group resolution (because the
// token carried no group claim) and the cluster lookup fails, the error is
// surfaced as a failed HTTP response rather than silently ignored.
func TestResolveUserGroupsFallbackPropagatesClusterLookupError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	wc := newTestSessionController(t)
	lookupErr := errors.New("cluster unreachable")
	wc.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
		return nil, lookupErr
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	// No "groups" key set at all, simulating a token without a groups claim.

	cug := ClusterUserGroup{Username: "alice@example.com", Clustername: "prod"}
	groups, ok := wc.resolveUserGroups(ctx, context.Background(), cug, nil, zaptest.NewLogger(t).Sugar())

	require.False(t, ok, "resolveUserGroups must fail when the cluster-based fallback lookup errors")
	require.Nil(t, groups)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}
