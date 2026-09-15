package breakglass

import (
	"context"
	"errors"
	"fmt"
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
	assert.Contains(t, result.allApprovers, "alice@example.com")
	assert.NotContains(t, result.allApprovers, "bob@example.com")
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

	// Only the requested escalation contributes notification recipients.
	count := 0
	for _, a := range result.allApprovers {
		if a == "alice@example.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "alice should appear exactly once (deduplication)")
	assert.Contains(t, result.allApprovers, "bob@example.com")
	assert.NotContains(t, result.allApprovers, "charlie@example.com")
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

func TestResolveAndAddGroupMembersPreservesResolutionForExclusions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		members map[string][]string
		known   bool
	}{
		{name: "unavailable"},
		{name: "failed", members: map[string][]string{}},
		{name: "empty", members: map[string][]string{"team": nil}, known: true},
		{name: "capped", members: map[string][]string{"team": {"first@example.com", "excluded@example.com"}}, known: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := &BreakglassSessionController{}
			if tc.members != nil {
				ctrl.escalationManager = &testEscalationLookup{resolver: &MockGroupResolver{members: tc.members}}
			}
			result := &escalationResolutionResult{approversByGroup: map[string][]string{}, allApprovers: make([]string, MaxTotalApprovers-1)}
			for i := range result.allApprovers {
				result.allApprovers[i] = fmt.Sprintf("existing-%d@example.com", i)
			}
			esc := &breakglassv1alpha1.BreakglassEscalation{Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{Groups: []string{"team"}},
			}}
			ctrl.resolveAndAddGroupMembers(context.Background(), esc, result, zap.NewNop().Sugar())
			members, known := result.approversByGroup["team"]
			assert.Equal(t, tc.known, known)
			assert.Equal(t, tc.members["team"], members)
			assert.LessOrEqual(t, len(result.allApprovers), MaxTotalApprovers)
		})
	}
}

// A default-provider resolver must never supply restricted-provider recipients.
type notificationDefaultResolver struct{ called bool }

func (r *notificationDefaultResolver) Members(context.Context, string) ([]string, error) {
	r.called = true
	return []string{"outside@example.com"}, nil
}

func TestRestrictedNotificationProvidersNeverUseDefaultResolver(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			status map[string]map[string][]string
			want   []string
			known  bool
		}{
			{name: "missing map"},
			{name: "missing provider", status: map[string]map[string][]string{"outside": {"team": {"outside@example.com"}}}},
			{name: "missing group", status: map[string]map[string][]string{"allowed": {}}},
			{name: "known empty", status: map[string]map[string][]string{"allowed": {"team": nil}}, known: true},
			{name: "scoped members", status: map[string]map[string][]string{"allowed": {"team": {"inside@example.com"}}, "outside": {"team": {"outside@example.com"}}}, want: []string{"inside@example.com"}, known: true},
		} {
			t.Run(map[bool]string{false: "role", true: "legacy"}[legacy]+"/"+tc.name, func(t *testing.T) {
				resolver := &notificationDefaultResolver{}
				ctrl := &BreakglassSessionController{escalationManager: &testEscalationLookup{resolver: resolver}}
				esc := &breakglassv1alpha1.BreakglassEscalation{Spec: breakglassv1alpha1.BreakglassEscalationSpec{Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{Groups: []string{"team"}}}}
				if legacy {
					esc.Spec.AllowedIdentityProviders = []string{"allowed"}
				} else {
					esc.Spec.AllowedIdentityProvidersForApprovers = []string{"allowed"}
					// Role-specific restrictions take precedence if an old object
					// contains both forms despite current admission validation.
					esc.Spec.AllowedIdentityProviders = []string{"outside"}
				}
				esc.Status.IDPGroupMemberships = tc.status
				// A stale aggregate must not reintroduce another provider.
				esc.Status.ApproverGroupMembers = map[string][]string{"team": {"outside@example.com"}}
				result := &escalationResolutionResult{approversByGroup: map[string][]string{}}
				ctrl.resolveAndAddGroupMembers(context.Background(), esc, result, zap.NewNop().Sugar())
				assert.False(t, resolver.called)
				assert.Equal(t, tc.want, result.allApprovers)
				_, known := result.approversByGroup["team"]
				assert.Equal(t, tc.known, known)
				assert.NotContains(t, result.allApprovers, "outside@example.com")
			})
		}
	}
}

type notificationEmptyDefaultResolver struct{ called bool }

func (r *notificationEmptyDefaultResolver) Members(context.Context, string) ([]string, error) {
	r.called = true
	return nil, nil // A successful empty group in the wrong provider is not proof.
}

func TestRestrictedNotificationPrivacyFilters(t *testing.T) {
	for _, filter := range []string{"excluded", "hidden"} {
		for _, legacy := range []bool{false, true} {
			for _, tc := range []struct {
				name     string
				status   map[string]map[string][]string
				snapshot map[string][]string
				want     []string
				suppress bool
			}{
				{name: "unknown suppresses despite default successful empty", suppress: true},
				{name: "scoped excludes member", status: map[string]map[string][]string{"allowed": {"secret": {"private@example.com"}}}, want: []string{"visible@example.com"}},
				{name: "scoped empty permits recipients", status: map[string]map[string][]string{"allowed": {"secret": nil}}, want: []string{"private@example.com", "visible@example.com"}},
				{name: "request snapshot remains authoritative", snapshot: map[string][]string{"secret": {"private@example.com"}}, want: []string{"visible@example.com"}},
			} {
				t.Run(filter+"/"+map[bool]string{false: "role", true: "legacy"}[legacy]+"/"+tc.name, func(t *testing.T) {
					resolver := &notificationEmptyDefaultResolver{}
					ctrl := &BreakglassSessionController{escalationManager: &testEscalationLookup{resolver: resolver}}
					esc := &breakglassv1alpha1.BreakglassEscalation{}
					if legacy {
						esc.Spec.AllowedIdentityProviders = []string{"allowed"}
					} else {
						esc.Spec.AllowedIdentityProvidersForApprovers = []string{"allowed"}
					}
					esc.Status.IDPGroupMemberships = tc.status
					esc.Spec.NotificationExclusions = &breakglassv1alpha1.NotificationExclusions{Groups: []string{"secret"}}
					esc.Spec.Approvers.HiddenFromUI = []string{"secret"}
					// secret is deliberately not an approver group, so normal
					// candidate collection need not have resolved it.
					candidates := []string{"private@example.com", "visible@example.com"}
					var got []string
					var suppressed bool
					if filter == "excluded" {
						got, suppressed = ctrl.filterExcludedNotificationRecipients(zap.NewNop().Sugar(), candidates, tc.snapshot, esc)
					} else {
						got, suppressed = ctrl.filterHiddenFromUIRecipients(zap.NewNop().Sugar(), candidates, tc.snapshot, esc)
					}
					assert.Equal(t, tc.want, got)
					assert.Equal(t, tc.suppress, suppressed)
					assert.False(t, resolver.called)
				})
			}
		}
	}
}

func TestRestrictedNotificationPrivacySnapshotFiltersAndSendsVisibleRecipient(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProvidersForApprovers: []string{"allowed"},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"team"},
			},
			NotificationExclusions: &breakglassv1alpha1.NotificationExclusions{Groups: []string{"private"}},
		},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{IDPGroupMemberships: map[string]map[string][]string{
			"allowed": {"private": {"private@example.com"}},
		}},
	}
	sender := &FakeMailSender{}
	controller := &BreakglassSessionController{log: zap.NewNop().Sugar(), mail: sender}
	approvers := []string{"private@example.com", "visible@example.com"}
	groups := map[string][]string{
		"team":    {"visible@example.com"},
		"private": {"private@example.com"},
	}

	filtered, suppressed := controller.filterExcludedNotificationRecipients(controller.log, approvers, groups, esc)
	require.False(t, suppressed)
	assert.Equal(t, []string{"visible@example.com"}, filtered)
	controller.sendOnRequestEmailsByGroup(controller.log, breakglassv1alpha1.BreakglassSession{}, "requester@example.com", "requester", filtered, groups, esc)

	assert.Equal(t, 1, sender.SendCallCount)
	assert.Equal(t, []string{"visible@example.com"}, sender.LastRecivers)
}

func TestRestrictedNotificationMembershipPreservesOrderAndExactIdentity(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{Spec: breakglassv1alpha1.BreakglassEscalationSpec{AllowedIdentityProvidersForApprovers: []string{"first", "second"}}, Status: breakglassv1alpha1.BreakglassEscalationStatus{IDPGroupMemberships: map[string]map[string][]string{
		"first":  {"team": {"b@example.com", "a@example.com", "b@example.com"}},
		"second": {"team": {"a@example.com", "A@example.com", "c@example.com", "c@example.com"}},
	}}}
	members, known := restrictedNotificationGroupMembers(esc, "team")
	require.True(t, known)
	assert.Equal(t, []string{"b@example.com", "a@example.com", "A@example.com", "c@example.com"}, members)
	assert.Equal(t, []string{"b@example.com", "a@example.com", "b@example.com"}, esc.Status.IDPGroupMemberships["first"]["team"])
}

func TestLargeNotificationSnapshotExcludesTailMemberBeyondRecipientCap(t *testing.T) {
	members := make([]string, MaxApproverGroupMembers+10)
	for i := range members {
		members[i] = fmt.Sprintf("member-%d@example.com", i)
	}
	members[len(members)-1] = "excluded@example.com"
	esc := &breakglassv1alpha1.BreakglassEscalation{Spec: breakglassv1alpha1.BreakglassEscalationSpec{
		AllowedIdentityProvidersForApprovers: []string{"provider"},
		Approvers:                            breakglassv1alpha1.BreakglassEscalationApprovers{Groups: []string{"team"}, Users: []string{"excluded@example.com", "visible@example.com"}},
		NotificationExclusions:               &breakglassv1alpha1.NotificationExclusions{Groups: []string{"team"}},
	}, Status: breakglassv1alpha1.BreakglassEscalationStatus{IDPGroupMemberships: map[string]map[string][]string{"provider": {"team": members}}}}
	sender := &FakeMailSender{}
	controller := &BreakglassSessionController{log: zap.NewNop().Sugar(), mail: sender}
	result := &escalationResolutionResult{allApprovers: []string{"excluded@example.com", "visible@example.com"}, approversByGroup: map[string][]string{"_explicit_users": {"excluded@example.com", "visible@example.com"}}}
	controller.resolveAndAddGroupMembers(context.Background(), esc, result, controller.log)
	require.Equal(t, members, result.approversByGroup["team"], "privacy snapshot must remain complete")
	expected := append([]string{"excluded@example.com", "visible@example.com"}, members[:MaxApproverGroupMembers]...)
	require.Equal(t, expected, result.allApprovers, "candidate cap and first-seen order must remain unchanged")
	filtered, _ := controller.filterExcludedNotificationRecipients(controller.log, result.allApprovers, result.approversByGroup, esc)
	require.Equal(t, []string{"visible@example.com"}, filtered, "tail membership must exclude even an explicit recipient")
	controller.sendOnRequestEmailsByGroup(controller.log, breakglassv1alpha1.BreakglassSession{}, "requester@example.com", "requester", filtered, result.approversByGroup, esc)
	assert.Equal(t, 1, sender.SendCallCount)
	assert.Equal(t, []string{"visible@example.com"}, sender.LastRecivers)
	// A recipient remains eligible through the explicit-user path; its tail group
	// attribution is omitted because the render scan is capped.
	sender.SendCallCount = 0
	result.approversByGroup["_explicit_users"] = append(result.approversByGroup["_explicit_users"], members[len(members)-2])
	controller.sendOnRequestEmailsByGroup(controller.log, breakglassv1alpha1.BreakglassSession{}, "requester@example.com", "requester", []string{members[len(members)-2], members[len(members)-2]}, result.approversByGroup, esc)
	assert.Equal(t, 1, sender.SendCallCount)
	assert.Equal(t, []string{members[len(members)-2]}, sender.LastRecivers)
	assert.NotContains(t, sender.LastBody, `<span class="group-badge">team</span>`, "tail member must not receive a group attribution from the capped prefix")
	hiddenEsc := esc.DeepCopy()
	hiddenEsc.Spec.NotificationExclusions = nil
	hiddenEsc.Spec.Approvers.HiddenFromUI = []string{"team"}
	hidden, _ := controller.filterHiddenFromUIRecipients(controller.log, []string{"excluded@example.com"}, result.approversByGroup, hiddenEsc)
	assert.Empty(t, hidden, "tail member hidden through the complete group snapshot must not receive email")
}

func TestLargeNotificationAttributionKeepsCrossGroupTailRecipient(t *testing.T) {
	members := make([]string, MaxApproverGroupMembers+1)
	for i := range members {
		members[i] = fmt.Sprintf("large-%d@example.com", i)
	}
	tail := members[len(members)-1]
	esc := &breakglassv1alpha1.BreakglassEscalation{Spec: breakglassv1alpha1.BreakglassEscalationSpec{Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{Groups: []string{"large", "overlap"}}}}
	sender := &FakeMailSender{}
	controller := &BreakglassSessionController{log: zap.NewNop().Sugar(), mail: sender}
	groups := map[string][]string{"large": members, "overlap": {tail}}
	controller.sendOnRequestEmailsByGroup(controller.log, breakglassv1alpha1.BreakglassSession{}, "requester@example.com", "requester", []string{tail}, groups, esc)
	require.Equal(t, 1, sender.SendCallCount)
	assert.Equal(t, []string{tail}, sender.LastRecivers)
	assert.Contains(t, sender.LastBody, "overlap")
	assert.NotContains(t, sender.LastBody, `<span class="group-badge">large</span>`)
}
