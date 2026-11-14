package breakglass

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var errSpokeUnreachable = errors.New("remote SelfSubjectReview failed: connection refused")

// counterValue reads a single labelled counter value from a CounterVec.
func counterValue(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	m := &dto.Metric{}
	counter, err := vec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	require.NoError(t, counter.(prometheus.Metric).Write(m))
	return m.GetCounter().GetValue()
}

// failOpenSession builds a pending session for cluster "failopen-cluster".
func failOpenSession() *breakglassv1alpha1.BreakglassSession {
	return &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "failopen-session", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "failopen-cluster",
			User:         "requester@example.com",
			GrantedGroup: "failopen-admin",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
	}
}

// failOpenEscalation grants approval to members of the "cluster-approvers" group.
// Approvers.Groups is used (not Users) so that group resolution is load-bearing,
// and Status.ApproverGroupMembers is left nil so the group check falls through to
// the approverGroups / requestContextGroups comparison.
func failOpenEscalation() *breakglassv1alpha1.BreakglassEscalation {
	return &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "failopen-escalation"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"failopen-cluster"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "failopen-admin",
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"cluster-approvers"},
			},
		},
	}
}

// TestApprovalGroupLookupFailureIsObservable pins the fail-open bug at
// session_controller_approval_utils.go: when the cluster-side group lookup
// fails, the JWT-claim groups were previously substituted wholesale and the
// authorization decision proceeded silently on unverified groups.
//
// The decision itself is preserved (see the asymmetric-failure rationale in
// recordUnverifiedApproverGroupsDecision), but the silent part is fixed: the
// lookup error is always logged, a dedicated metric increments, and when the
// fallback is load-bearing for an ALLOW a distinct audit event is emitted.
func TestApprovalGroupLookupFailureIsObservable(t *testing.T) {
	tests := []struct {
		name string
		// groups placed in the gin request context (JWT claims, unverified)
		requestContextGroups []string
		// nil means the lookup succeeds and returns verifiedGroups
		lookupErr      error
		verifiedGroups []string

		expectAllowed        bool
		expectReason         ApprovalDenialReason
		expectLookupFailures float64
		expectUnverifiedDecs float64
		expectAuditEvent     bool
	}{
		{
			name:                 "lookup error with load-bearing JWT groups is allowed but audited",
			requestContextGroups: []string{"cluster-approvers"},
			lookupErr:            errSpokeUnreachable,
			expectAllowed:        true,
			expectLookupFailures: 1,
			expectUnverifiedDecs: 1,
			expectAuditEvent:     true,
		},
		{
			name:                 "lookup error with non-approver JWT groups still denies",
			requestContextGroups: []string{"some-other-group"},
			lookupErr:            errSpokeUnreachable,
			expectAllowed:        false,
			expectReason:         ApprovalDenialNotAnApprover,
			expectLookupFailures: 1,
			expectUnverifiedDecs: 0,
			expectAuditEvent:     false,
		},
		{
			name:                 "lookup error with no JWT groups denies as unauthenticated",
			requestContextGroups: nil,
			lookupErr:            errSpokeUnreachable,
			expectAllowed:        false,
			expectReason:         ApprovalDenialUnauthenticated,
			expectLookupFailures: 1,
			expectUnverifiedDecs: 0,
			expectAuditEvent:     false,
		},
		{
			name:                 "no regression: verified groups succeed with no fallback signals",
			requestContextGroups: []string{"cluster-approvers"},
			lookupErr:            nil,
			verifiedGroups:       []string{"cluster-approvers"},
			expectAllowed:        true,
			expectLookupFailures: 0,
			expectUnverifiedDecs: 0,
			expectAuditEvent:     false,
		},
		{
			name:                 "no regression: verified groups deny a non-approver even if JWT claims one",
			requestContextGroups: []string{"cluster-approvers"},
			lookupErr:            nil,
			verifiedGroups:       []string{"unprivileged"},
			expectAllowed:        false,
			expectReason:         ApprovalDenialNotAnApprover,
			expectLookupFailures: 0,
			expectUnverifiedDecs: 0,
			expectAuditEvent:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const cluster = "failopen-cluster"
			baseFailures := counterValue(t, metrics.ApprovalGroupLookupFailures, cluster)
			baseUnverified := counterValue(t, metrics.ApprovalUnverifiedGroupDecisions, cluster)

			ctrl := newApprovalAuthorizationTestController(t, failOpenSession(), failOpenEscalation())
			mockAudit := NewMockAuditEmitter(true)
			ctrl.WithAuditService(mockAudit)
			ctrl.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
				if tt.lookupErr != nil {
					return nil, tt.lookupErr
				}
				return tt.verifiedGroups, nil
			}

			c := newApprovalAuthorizationTestContext("approver@example.com", "")
			if tt.requestContextGroups != nil {
				c.Set("groups", tt.requestContextGroups)
			}

			result := ctrl.checkApprovalAuthorization(c, *failOpenSession())

			require.Equal(t, tt.expectAllowed, result.Allowed, "message: %s", result.Message)
			if !tt.expectAllowed {
				require.Equal(t, tt.expectReason, result.Reason)
			}

			require.Equal(t, tt.expectLookupFailures,
				counterValue(t, metrics.ApprovalGroupLookupFailures, cluster)-baseFailures,
				"ApprovalGroupLookupFailures delta")
			require.Equal(t, tt.expectUnverifiedDecs,
				counterValue(t, metrics.ApprovalUnverifiedGroupDecisions, cluster)-baseUnverified,
				"ApprovalUnverifiedGroupDecisions delta")

			var unverifiedEvents []*audit.Event
			for _, ev := range mockAudit.GetEvents() {
				if ev.Type == audit.EventSessionApprovalUnverifiedGroups {
					unverifiedEvents = append(unverifiedEvents, ev)
				}
			}
			if !tt.expectAuditEvent {
				require.Empty(t, unverifiedEvents,
					"no unverified-groups audit event expected for this case")
				return
			}

			require.Len(t, unverifiedEvents, 1)
			ev := unverifiedEvents[0]
			require.Equal(t, audit.SeverityWarning, ev.Severity)
			require.Equal(t, "approver@example.com", ev.Actor.User)
			require.Equal(t, cluster, ev.Target.Cluster)
			require.Equal(t, "failopen-session", ev.Target.Name)
			require.Equal(t, "unverified_request_context", ev.Details["groupBasis"])
			require.Equal(t, true, ev.Details["loadBearing"])
			require.Equal(t, "allowed", ev.Details["authorization"])
		})
	}
}

func TestEmptyResolvedApproverGroupDoesNotFallBackToTokenGroup(t *testing.T) {
	escalation := failOpenEscalation()
	escalation.Status.ApproverGroupMembers = map[string][]string{
		"cluster-approvers": {},
	}

	ctrl := newApprovalAuthorizationTestController(t, failOpenSession(), escalation)
	ctrl.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
		return []string{"cluster-approvers"}, nil
	}

	c := newApprovalAuthorizationTestContext("approver@example.com", "")
	c.Set("groups", []string{"cluster-approvers"})

	result := ctrl.checkApprovalAuthorization(c, *failOpenSession())

	require.False(t, result.Allowed)
	require.Equal(t, ApprovalDenialNotAnApprover, result.Reason)
}

// TestApprovalUnverifiedGroupsAuditSurvivesDisabledAuditService ensures the
// observability path degrades safely: with audit disabled the metric still
// increments and the decision is unchanged (no panic, no lockout).
func TestApprovalUnverifiedGroupsAuditSurvivesDisabledAuditService(t *testing.T) {
	const cluster = "failopen-cluster"
	baseUnverified := counterValue(t, metrics.ApprovalUnverifiedGroupDecisions, cluster)

	ctrl := newApprovalAuthorizationTestController(t, failOpenSession(), failOpenEscalation())
	mockAudit := NewMockAuditEmitter(false) // disabled
	ctrl.WithAuditService(mockAudit)
	ctrl.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
		return nil, errSpokeUnreachable
	}

	c := newApprovalAuthorizationTestContext("approver@example.com", "")
	c.Set("groups", []string{"cluster-approvers"})

	result := ctrl.checkApprovalAuthorization(c, *failOpenSession())

	require.True(t, result.Allowed, "must not introduce a lockout when audit is disabled")
	require.Equal(t, float64(1),
		counterValue(t, metrics.ApprovalUnverifiedGroupDecisions, cluster)-baseUnverified)
	require.Empty(t, mockAudit.GetEvents(), "disabled audit service must not receive events")
}

// TestApprovalGroupLookupNotRetriedAfterFailureWithinRequest verifies the
// per-request negative cache: repeated authorization checks in one request must
// not re-hammer a known-failing spoke, and must not silently regain "verified"
// status if a later call happens to succeed.
func TestApprovalGroupLookupNotRetriedAfterFailureWithinRequest(t *testing.T) {
	ctrl := newApprovalAuthorizationTestController(t, failOpenSession(), failOpenEscalation())
	ctrl.WithAuditService(NewMockAuditEmitter(true))

	calls := 0
	ctrl.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
		calls++
		return nil, errSpokeUnreachable
	}

	c := newApprovalAuthorizationTestContext("approver@example.com", "")
	c.Set("groups", []string{"cluster-approvers"})

	session := *failOpenSession()
	first := ctrl.checkApprovalAuthorization(c, session)
	second := ctrl.checkApprovalAuthorization(c, session)

	require.True(t, first.Allowed)
	require.True(t, second.Allowed)
	require.Equal(t, 1, calls, "failing spoke lookup must not be retried within the same request")
}

// TestApprovalVerifiedGroupsAreCachedNotDowngraded is the companion no-regression
// case: a successful lookup is cached and the second check reuses the verified
// groups without emitting any fallback signal.
func TestApprovalVerifiedGroupsAreCachedNotDowngraded(t *testing.T) {
	const cluster = "failopen-cluster"
	baseUnverified := counterValue(t, metrics.ApprovalUnverifiedGroupDecisions, cluster)

	ctrl := newApprovalAuthorizationTestController(t, failOpenSession(), failOpenEscalation())
	mockAudit := NewMockAuditEmitter(true)
	ctrl.WithAuditService(mockAudit)

	calls := 0
	ctrl.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
		calls++
		return []string{"cluster-approvers"}, nil
	}

	c := newApprovalAuthorizationTestContext("approver@example.com", "")
	session := *failOpenSession()

	require.True(t, ctrl.checkApprovalAuthorization(c, session).Allowed)
	require.True(t, ctrl.checkApprovalAuthorization(c, session).Allowed)
	require.Equal(t, 1, calls, "verified groups should be cached per request")
	require.Equal(t, float64(0),
		counterValue(t, metrics.ApprovalUnverifiedGroupDecisions, cluster)-baseUnverified)
	require.Empty(t, mockAudit.GetEvents())
}

// TestApprovalUnverifiedGroupsEventTypeClassification pins the audit
// classification of the new event type.
func TestApprovalUnverifiedGroupsEventTypeClassification(t *testing.T) {
	require.Equal(t, audit.SeverityWarning,
		audit.SeverityForEventType(audit.EventSessionApprovalUnverifiedGroups))
	require.True(t, audit.IsSensitiveEvent(audit.EventSessionApprovalUnverifiedGroups))
	require.Equal(t, audit.EventType("session.approval_unverified_groups"),
		audit.EventSessionApprovalUnverifiedGroups)
}

func init() {
	gin.SetMode(gin.TestMode)
}

// An ambiguous approver group (for example a top-level group plus a same-named
// nested subgroup, whose members carry the same short group claim) is stored
// as an empty entry, so a token carrying the group claim cannot approve.
// A group another provider resolved stays authoritative.
func TestAmbiguousApproverGroupDoesNotApproveByTokenGroup(t *testing.T) {
	tests := []struct {
		name    string
		members map[string][]string
	}{
		{name: "ambiguous everywhere: empty entry", members: map[string][]string{"cluster-approvers": {}}},
		{name: "another provider resolved other members", members: map[string][]string{"cluster-approvers": {"b-user@example.com"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			escalation := failOpenEscalation()
			escalation.Status.ApproverGroupMembers = tt.members
			ctrl := newApprovalAuthorizationTestController(t, failOpenSession(), escalation)
			ctrl.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
				return []string{"cluster-approvers"}, nil
			}
			c := newApprovalAuthorizationTestContext("approver@example.com", "")
			c.Set("groups", []string{"cluster-approvers"})

			result := ctrl.checkApprovalAuthorization(c, *failOpenSession())

			require.False(t, result.Allowed)
			require.Equal(t, ApprovalDenialNotAnApprover, result.Reason)
		})
	}
}

// --require-synced-approver-groups closes the window before an approver
// group's first sync, when approval would otherwise fall back to cluster or
// token groups (which members of a same-named nested group also carry).
func TestRequireSyncedApproverGroups(t *testing.T) {
	tests := []struct {
		name          string
		require       bool
		members       map[string][]string // nil: not synced yet
		clusterLookup error               // non-nil: cluster lookup fails, token groups are used
		want          ApprovalDenialReason
	}{
		{name: "flag off, not synced: cluster-group fallback approves"},
		{name: "flag off, not synced: token-group fallback approves", clusterLookup: errors.New("spoke down")},
		{name: "flag on, not synced: cluster group denied", require: true, want: ApprovalDenialApproverGroupsNotSynced},
		{name: "flag on, not synced: token group denied", require: true, clusterLookup: errors.New("spoke down"), want: ApprovalDenialApproverGroupsNotSynced},
		{name: "flag on, synced with the approver: approves", require: true, members: map[string][]string{"cluster-approvers": {"approver@example.com"}}},
		{name: "flag on, synced without the approver: not an approver", require: true, members: map[string][]string{"cluster-approvers": {"other@example.com"}}, want: ApprovalDenialNotAnApprover},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			escalation := failOpenEscalation()
			escalation.Status.ApproverGroupMembers = tt.members
			ctrl := newApprovalAuthorizationTestController(t, failOpenSession(), escalation).WithRequireSyncedApproverGroups(tt.require)
			ctrl.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
				if tt.clusterLookup != nil {
					return nil, tt.clusterLookup
				}
				return []string{"cluster-approvers"}, nil
			}
			c := newApprovalAuthorizationTestContext("approver@example.com", "")
			c.Set("groups", []string{"cluster-approvers"})

			result := ctrl.checkApprovalAuthorization(c, *failOpenSession())

			require.Equal(t, tt.want == ApprovalDenialNone, result.Allowed, "reason %s", result.Reason)
			require.Equal(t, tt.want, result.Reason)
		})
	}
}

// Per-IdP memberships authorize approval only while they are part of the
// group's current resolution (an ApproverGroupMembers entry that contains the
// member). Stale snapshots, for example left behind after a fallback to legacy
// mode, must not approve.
func TestStaleProviderGroupMembershipDoesNotApprove(t *testing.T) {
	tests := []struct {
		name      string
		aggregate map[string][]string
		perIDP    []string
		allowed   bool
	}{
		{
			name:      "no current entry for the group, token without the group",
			aggregate: map[string][]string{"other-group": {"someone@example.com"}},
			perIDP:    []string{"approver@example.com"},
		},
		{
			name:      "member removed upstream after a resync",
			aggregate: map[string][]string{"cluster-approvers": {"current@example.com"}},
			perIDP:    []string{"approver@example.com"},
		},
		{
			name:      "current member of the current resolution",
			aggregate: map[string][]string{"cluster-approvers": {"approver@example.com"}},
			perIDP:    []string{"approver@example.com"},
			allowed:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			escalation := failOpenEscalation()
			escalation.Status.ApproverGroupMembers = tt.aggregate
			escalation.Status.IDPGroupMemberships = map[string]map[string][]string{
				"idp-a": {"cluster-approvers": tt.perIDP},
			}
			ctrl := newApprovalAuthorizationTestController(t, failOpenSession(), escalation)
			ctrl.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
				return []string{}, nil
			}
			c := newApprovalAuthorizationTestContext("approver@example.com", "idp-a")
			c.Set("groups", []string{})

			result := ctrl.checkApprovalAuthorization(c, *failOpenSession())

			require.Equal(t, tt.allowed, result.Allowed, "reason %s", result.Reason)
			if !tt.allowed {
				// The denial must come from group membership, not from an
				// unrelated check such as the identity provider allow-list.
				require.Equal(t, ApprovalDenialNotAnApprover, result.Reason)
			}
		})
	}
}

func largeProviderGroupEscalation(size int, stale string) *breakglassv1alpha1.BreakglassEscalation {
	members := make([]string, 0, size)
	for i := 0; i < size; i++ {
		members = append(members, fmt.Sprintf("member-%04d@example.com", i))
	}
	escalation := failOpenEscalation()
	escalation.Status.ApproverGroupMembers = map[string][]string{"cluster-approvers": members}
	escalation.Status.IDPGroupMemberships = map[string]map[string][]string{
		"idp-a": {"cluster-approvers": append(append([]string(nil), members...), stale)},
	}
	return escalation
}

// With a 1,000-member group the stale-membership guard still denies a member
// that is only in the per-IdP snapshot, a current member still approves, and
// an unrelated caller is denied.
func TestLargeProviderGroupMembershipCheck(t *testing.T) {
	escalation := largeProviderGroupEscalation(1000, "stale@example.com")
	for caller, allowed := range map[string]bool{
		"member-0999@example.com": true,
		"stale@example.com":       false,
		"unrelated@example.com":   false,
	} {
		t.Run(caller, func(t *testing.T) {
			ctrl := newApprovalAuthorizationTestController(t, failOpenSession(), escalation)
			ctrl.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) { return []string{}, nil }
			c := newApprovalAuthorizationTestContext(caller, "idp-a")
			c.Set("groups", []string{})
			result := ctrl.checkApprovalAuthorization(c, *failOpenSession())
			require.Equal(t, allowed, result.Allowed)
			if !allowed {
				require.Equal(t, ApprovalDenialNotAnApprover, result.Reason)
			}
		})
	}
}

// BenchmarkLargeProviderGroupUnrelatedCaller measures an approval check for a
// caller outside a 1,000-member group; the aggregate is scanned only for a
// per-IdP member that matches the caller, so the cost stays linear.
func BenchmarkLargeProviderGroupUnrelatedCaller(b *testing.B) {
	escalation := largeProviderGroupEscalation(1000, "stale@example.com")
	ctrl := newApprovalAuthorizationTestController(b, failOpenSession(), escalation)
	ctrl.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) { return []string{}, nil }
	c := newApprovalAuthorizationTestContext("unrelated@example.com", "idp-a")
	c.Set("groups", []string{})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctrl.checkApprovalAuthorization(c, *failOpenSession())
	}
}
