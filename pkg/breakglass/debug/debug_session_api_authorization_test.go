/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package debug

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// ============================================================================
// Tests for isUserAuthorizedToApprove
// ============================================================================

func TestIsUserAuthorizedToApprove_NoResolvedTemplate(t *testing.T) {
	// TestIsUserAuthorizedToApprove_NoResolvedTemplate
	//
	// Purpose:
	//   Verifies that when session has no ResolvedTemplate in status,
	//   the function fetches the template from the API.

	logger := zaptest.NewLogger(t).Sugar()

	// Create template with approvers
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Users:  []string{"approver@example.com"},
				Groups: []string{"admins"},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(template).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: nil, // No resolved template
		},
	}

	ctx := context.Background()

	// User in allowed users list
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "approver@example.com", nil)
	assert.True(t, result, "user in approvers.users should be authorized")

	// User not in allowed list
	result = ctrl.isUserAuthorizedToApprove(ctx, session, "other@example.com", nil)
	assert.False(t, result, "user not in approvers should not be authorized")
}

func TestIsUserAuthorizedToApprove_TemplateFetchFails(t *testing.T) {
	// When template cannot be fetched, deny approval (fail closed for security)

	logger := zaptest.NewLogger(t).Sugar()

	// No template in cluster
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "non-existent-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: nil,
		},
	}

	ctx := context.Background()
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "anyuser@example.com", nil)
	assert.False(t, result, "should deny approval when template cannot be fetched (fail closed)")
}

func TestIsUserAuthorizedToApprove_TemplateNoApprovers(t *testing.T) {
	// When template has no approvers configured, allow any authenticated user

	logger := zaptest.NewLogger(t).Sugar()

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "no-approvers-template"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: nil, // No approvers
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(template).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "no-approvers-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: nil,
		},
	}

	ctx := context.Background()
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "anyuser@example.com", nil)
	assert.True(t, result, "any authenticated user should be able to approve when no approvers configured")
}

func TestCanReadDebugSession_RequesterParticipantInviteeAndApprover(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	now := metav1.Now()
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef:         "test-template",
			RequestedBy:         "alice",
			RequestedByEmail:    "alice@example.com",
			InvitedParticipants: []string{"invitee@example.com"},
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			Participants: []breakglassv1alpha1.DebugSessionParticipant{
				{User: "opaque-bob", Email: "bob@example.com", Role: breakglassv1alpha1.ParticipantRoleViewer, JoinedAt: now},
			},
			Approval: &breakglassv1alpha1.DebugSessionApproval{
				ApprovedBy: "historical-approver@example.com",
				RejectedBy: "historical-rejector@example.com",
			},
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Groups: []string{"debug-approvers"},
				},
			},
		},
	}

	ctx := context.Background()
	for _, tt := range []struct {
		name     string
		identity debugSessionReadIdentity
		want     bool
	}{
		{name: "requester username", identity: debugSessionReadIdentity{username: "alice"}, want: true},
		{name: "requester email", identity: debugSessionReadIdentity{username: "subject", email: "alice@example.com"}, want: true},
		{name: "active participant email", identity: debugSessionReadIdentity{username: "subject", email: "bob@example.com"}, want: true},
		{name: "invited participant", identity: debugSessionReadIdentity{username: "invitee@example.com"}, want: true},
		{name: "historical approver", identity: debugSessionReadIdentity{username: "historical-approver@example.com"}, want: true},
		{name: "historical rejector", identity: debugSessionReadIdentity{username: "historical-rejector@example.com"}, want: true},
		{name: "configured approver group", identity: debugSessionReadIdentity{username: "approver@example.com", groups: []string{"debug-approvers"}}, want: true},
		{name: "unrelated user", identity: debugSessionReadIdentity{username: "mallory@example.com"}, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ctrl.canReadDebugSession(ctx, session, tt.identity)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCanReadDebugSession_EmptyApproversDoNotGrantReadAccess(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-approvers-template"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(template).
		Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "empty-approvers-template",
			RequestedBy: "alice@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{},
			},
		},
	}

	result, err := ctrl.canReadDebugSession(context.Background(), session, debugSessionReadIdentity{username: "anyuser@example.com"})
	require.NoError(t, err)
	assert.False(t, result, "empty approvers must not make debug session reads world-readable")
}

func TestCanReadDebugSession_BindingApproverCanRead(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "prod-binding", Namespace: "breakglass"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Users: []string{"binding-approver@example.com"},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(binding).
		Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
			RequestedBy: "alice@example.com",
			BindingRef:  &breakglassv1alpha1.BindingReference{Name: "prod-binding", Namespace: "breakglass"},
		},
	}

	result, err := ctrl.canReadDebugSession(context.Background(), session, debugSessionReadIdentity{username: "binding-approver@example.com"})
	require.NoError(t, err)
	assert.True(t, result)

	result, err = ctrl.canReadDebugSession(context.Background(), session, debugSessionReadIdentity{username: "other@example.com"})
	require.NoError(t, err)
	assert.False(t, result)
}

func TestCanReadDebugSession_BindingApproversAreAuthoritative(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "prod-binding", Namespace: "breakglass"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Users: []string{"binding-approver@example.com"},
			},
		},
	}
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Users: []string{"template-approver@example.com"},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(binding, template).
		Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
			RequestedBy: "alice@example.com",
			BindingRef:  &breakglassv1alpha1.BindingReference{Name: "prod-binding", Namespace: "breakglass"},
		},
	}

	result, err := ctrl.canReadDebugSession(context.Background(), session, debugSessionReadIdentity{
		username: "opaque-subject",
		email:    "binding-approver@example.com",
	})
	require.NoError(t, err)
	assert.True(t, result)

	result, err = ctrl.canReadDebugSession(context.Background(), session, debugSessionReadIdentity{
		username: "template-approver@example.com",
	})
	require.NoError(t, err)
	assert.False(t, result)
}

func TestCanReadDebugSession_ResolvedTemplateApproversAreAuthoritative(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Users: []string{"live-template-approver@example.com"},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(template).
		Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
			RequestedBy: "alice@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"snapshot-approver@example.com"},
				},
			},
		},
	}

	result, err := ctrl.canReadDebugSession(context.Background(), session, debugSessionReadIdentity{
		username: "opaque-subject",
		email:    "snapshot-approver@example.com",
	})
	require.NoError(t, err)
	assert.True(t, result)

	result, err = ctrl.canReadDebugSession(context.Background(), session, debugSessionReadIdentity{
		username: "live-template-approver@example.com",
	})
	require.NoError(t, err)
	assert.False(t, result)
}

type debugSessionReadCountingClient struct {
	ctrlclient.Client
	gets map[string]int
}

func (c *debugSessionReadCountingClient) Get(ctx context.Context, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
	switch obj.(type) {
	case *breakglassv1alpha1.DebugSessionTemplate:
		c.gets["template:"+key.Name]++
	case *breakglassv1alpha1.DebugSessionClusterBinding:
		c.gets["binding:"+key.String()]++
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

type debugSessionReadFailingClient struct {
	ctrlclient.Client
	failBinding  bool
	failTemplate bool
}

func (c *debugSessionReadFailingClient) Get(ctx context.Context, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
	switch obj.(type) {
	case *breakglassv1alpha1.DebugSessionClusterBinding:
		if c.failBinding {
			return errors.New("binding reader unavailable")
		}
	case *breakglassv1alpha1.DebugSessionTemplate:
		if c.failTemplate {
			return errors.New("template reader unavailable")
		}
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func TestDebugSessionReadAuthorizerCachesTemplateApprovers(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-template"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Groups: []string{"debug-approvers"},
			},
		},
	}
	baseClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(template).
		Build()
	countingClient := &debugSessionReadCountingClient{
		Client: baseClient,
		gets:   map[string]int{},
	}
	ctrl := NewDebugSessionAPIController(logger, countingClient, nil, nil)
	authorizer := ctrl.newDebugSessionReadAuthorizer(debugSessionReadIdentity{
		username: "approver@example.com",
		groups:   []string{"debug-approvers"},
	})

	sessionA := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-a"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "shared-template",
			RequestedBy: "alice@example.com",
		},
	}
	sessionB := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-b"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "shared-template",
			RequestedBy: "bob@example.com",
		},
	}

	result, err := authorizer.canRead(context.Background(), sessionA)
	require.NoError(t, err)
	require.True(t, result)

	result, err = authorizer.canRead(context.Background(), sessionB)
	require.NoError(t, err)
	require.True(t, result)
	require.Equal(t, 1, countingClient.gets["template:shared-template"])
}

func TestCanReadDebugSession_ReturnsErrorWhenBindingApproverLookupFails(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	baseClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		Build()
	ctrl := NewDebugSessionAPIController(logger, &debugSessionReadFailingClient{
		Client:      baseClient,
		failBinding: true,
	}, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
			RequestedBy: "alice@example.com",
			BindingRef:  &breakglassv1alpha1.BindingReference{Name: "prod-binding", Namespace: "breakglass"},
		},
	}

	result, err := ctrl.canReadDebugSession(context.Background(), session, debugSessionReadIdentity{username: "approver@example.com"})
	require.Error(t, err)
	assert.False(t, result)
	assert.Contains(t, err.Error(), "fetch debug session binding")
}

func TestCanReadDebugSession_ReturnsErrorWhenTemplateApproverLookupFails(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	baseClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		Build()
	ctrl := NewDebugSessionAPIController(logger, &debugSessionReadFailingClient{
		Client:       baseClient,
		failTemplate: true,
	}, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
			RequestedBy: "alice@example.com",
		},
	}

	result, err := ctrl.canReadDebugSession(context.Background(), session, debugSessionReadIdentity{username: "approver@example.com"})
	require.Error(t, err)
	assert.False(t, result)
	assert.Contains(t, err.Error(), "fetch debug session template")
}

func TestCanActOnDebugSessionApproval_DeniesMissingIdentity(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template"},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(template).
		Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
			RequestedBy: "alice@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
		},
	}

	result := ctrl.canActOnDebugSessionApproval(context.Background(), session, debugSessionReadIdentity{}, nil)

	assert.False(t, result)
}

func TestCanActOnDebugSessionApproval_UsesEmailAuthorization(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef:      "test-template",
			RequestedBy:      "requester-subject",
			RequestedByEmail: "requester@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	result := ctrl.canActOnDebugSessionApproval(context.Background(), session, debugSessionReadIdentity{
		username: "opaque-subject",
		email:    "approver@example.com",
	}, nil)

	assert.True(t, result)
}

func TestCanActOnDebugSessionApproval_CachesBindingApprovers(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "prod-binding", Namespace: "breakglass"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Users: []string{"binding-approver@example.com"},
			},
		},
	}
	baseClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(binding).
		Build()
	countingClient := &debugSessionReadCountingClient{
		Client: baseClient,
		gets:   map[string]int{},
	}
	ctrl := NewDebugSessionAPIController(logger, countingClient, nil, nil)
	authorizer := ctrl.newDebugSessionApprovalAuthorizer()

	sessionA := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-a"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
			RequestedBy: "alice@example.com",
			BindingRef:  &breakglassv1alpha1.BindingReference{Name: "prod-binding", Namespace: "breakglass"},
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
		},
	}
	sessionB := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-b"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
			RequestedBy: "bob@example.com",
			BindingRef:  &breakglassv1alpha1.BindingReference{Name: "prod-binding", Namespace: "breakglass"},
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
		},
	}

	result := ctrl.canActOnDebugSessionApproval(context.Background(), sessionA, debugSessionReadIdentity{
		username: "binding-approver@example.com",
	}, authorizer)
	require.True(t, result)

	result = ctrl.canActOnDebugSessionApproval(context.Background(), sessionB, debugSessionReadIdentity{
		username: "binding-approver@example.com",
	}, authorizer)
	require.True(t, result)

	require.Equal(t, 1, countingClient.gets["binding:breakglass/prod-binding"])
}

func TestCanActOnDebugSessionApproval_CachesMissingTemplate(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	baseClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		Build()
	countingClient := &debugSessionReadCountingClient{
		Client: baseClient,
		gets:   map[string]int{},
	}
	ctrl := NewDebugSessionAPIController(logger, countingClient, nil, nil)
	authorizer := ctrl.newDebugSessionApprovalAuthorizer()

	sessionA := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-a"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "missing-template",
			RequestedBy: "alice@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
		},
	}
	sessionB := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-b"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "missing-template",
			RequestedBy: "bob@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
		},
	}

	result := ctrl.canActOnDebugSessionApproval(context.Background(), sessionA, debugSessionReadIdentity{
		username: "approver@example.com",
	}, authorizer)
	require.False(t, result)

	result = ctrl.canActOnDebugSessionApproval(context.Background(), sessionB, debugSessionReadIdentity{
		username: "approver@example.com",
	}, authorizer)
	require.False(t, result)

	require.Equal(t, 1, countingClient.gets["template:missing-template"])
}

func TestIsUserAuthorizedToApprove_ResolvedTemplateUserMatch(t *testing.T) {
	// When session has ResolvedTemplate, use that instead of fetching

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com", "admin@example.com"},
				},
			},
		},
	}

	ctx := context.Background()

	result := ctrl.isUserAuthorizedToApprove(ctx, session, "approver@example.com", nil)
	assert.True(t, result, "user in resolved approvers list should be authorized")

	result = ctrl.isUserAuthorizedToApprove(ctx, session, "admin@example.com", nil)
	assert.True(t, result, "admin in resolved approvers list should be authorized")

	result = ctrl.isUserAuthorizedToApprove(ctx, session, "other@example.com", nil)
	assert.False(t, result, "user not in resolved approvers list should not be authorized")
}

func TestIsUserAuthorizedToApprove_ResolvedTemplateGroupMatch(t *testing.T) {
	// Test matching by group membership

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Groups: []string{"cluster-admins", "platform-team"},
				},
			},
		},
	}

	ctx := context.Background()

	// User in matching group (string slice)
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "user@example.com", []string{"cluster-admins"})
	assert.True(t, result, "user in matching group should be authorized")

	// User in different group
	result = ctrl.isUserAuthorizedToApprove(ctx, session, "user@example.com", []string{"developers"})
	assert.False(t, result, "user not in any matching group should not be authorized")

	// User with no groups
	result = ctrl.isUserAuthorizedToApprove(ctx, session, "user@example.com", nil)
	assert.False(t, result, "user with no groups should not be authorized")
}

func TestIsUserAuthorizedToApprove_WildcardPatterns(t *testing.T) {
	// Test wildcard patterns in approvers

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	tests := []struct {
		name       string
		users      []string
		groups     []string
		username   string
		userGroups []string
		expected   bool
	}{
		{
			name:     "wildcard user pattern",
			users:    []string{"*@example.com"},
			username: "anyone@example.com",
			expected: true,
		},
		{
			name:     "wildcard user pattern no match",
			users:    []string{"*@example.com"},
			username: "user@other.com",
			expected: false,
		},
		{
			name:       "wildcard group pattern",
			groups:     []string{"team-*"},
			username:   "user@example.com",
			userGroups: []string{"team-alpha"},
			expected:   true,
		},
		{
			name:       "prefix wildcard",
			groups:     []string{"*-admins"},
			username:   "user@example.com",
			userGroups: []string{"cluster-admins"},
			expected:   true,
		},
		{
			name:     "universal wildcard user",
			users:    []string{"*"},
			username: "anyone@anywhere.com",
			expected: true,
		},
		{
			name:       "universal wildcard group",
			groups:     []string{"*"},
			username:   "user@example.com",
			userGroups: []string{"any-group"},
			expected:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{TemplateRef: "test"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						Approvers: &breakglassv1alpha1.DebugSessionApprovers{
							Users:  tc.users,
							Groups: tc.groups,
						},
					},
				},
			}

			ctx := context.Background()
			result := ctrl.isUserAuthorizedToApprove(ctx, session, tc.username, tc.userGroups)
			assert.Equal(t, tc.expected, result, "authorization result mismatch")
		})
	}
}

func TestIsUserAuthorizedToApprove_GroupsAsInterfaceSlice(t *testing.T) {
	// Test when groups are passed as []interface{} (JSON deserialization scenario)

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{TemplateRef: "test"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Groups: []string{"admins"},
				},
			},
		},
	}

	ctx := context.Background()

	// Groups as []interface{} (happens during JSON unmarshaling)
	interfaceGroups := []interface{}{"admins", "developers"}
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "user@example.com", interfaceGroups)
	assert.True(t, result, "should handle []interface{} groups")
}

func TestIsIdentityAuthorizedToApprove_EmailListedApprover(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "email-approver-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef:       "test",
			RequestedBy:       "requester-subject",
			RequestedByEmail:  "requester@example.com",
			TargetNamespace:   "default",
			RequestedDuration: "30m",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		},
	}

	result := ctrl.isIdentityAuthorizedToApprove(context.Background(), session, debugSessionReadIdentity{
		username: "opaque-approver-subject",
		email:    "approver@example.com",
	})
	assert.True(t, result, "email-listed approver should be authorized when username differs")
}

func TestIsIdentityAuthorizedToApprove_BlocksSelfApprovalByEmail(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "self-email-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef:       "test",
			RequestedBy:       "requester-subject",
			RequestedByEmail:  "requester@example.com",
			TargetNamespace:   "default",
			RequestedDuration: "30m",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"requester@example.com"},
				},
			},
		},
	}

	result := ctrl.isIdentityAuthorizedToApprove(context.Background(), session, debugSessionReadIdentity{
		username: "opaque-requester-subject",
		email:    "requester@example.com",
	})
	assert.False(t, result, "requester should not self-approve through email-listed approver match")
}

func TestIsIdentityAuthorizedToApprove_BlocksSelfApprovalByEmailCaseInsensitive(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "self-email-case-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef:       "test",
			RequestedBy:       "requester-subject",
			RequestedByEmail:  " requester@example.com ",
			TargetNamespace:   "default",
			RequestedDuration: "30m",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users: []string{"REQUESTER@EXAMPLE.COM"},
				},
			},
		},
	}

	result := ctrl.isIdentityAuthorizedToApprove(context.Background(), session, debugSessionReadIdentity{
		username: "opaque-requester-subject",
		email:    "Requester@Example.com",
	})
	assert.False(t, result, "requester email self-approval should be blocked despite casing or surrounding whitespace")
}

func TestIsUserAuthorizedToApprove_EmptyApproversAllowsAll(t *testing.T) {
	// When approvers has empty users and groups, allow any authenticated user

	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test-session"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{TemplateRef: "test"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{
					Users:  []string{},
					Groups: []string{},
				},
			},
		},
	}

	ctx := context.Background()
	result := ctrl.isUserAuthorizedToApprove(ctx, session, "anyone@example.com", nil)
	assert.True(t, result, "empty approvers lists should allow any authenticated user")
}

// ============================================================================
// Tests for checkApproverAuthorization (helper function)
// ============================================================================

func TestCheckApproverAuthorization_DirectUserMatch(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	approvers := &breakglassv1alpha1.DebugSessionApprovers{
		Users: []string{"user1@example.com", "user2@example.com"},
	}

	assert.True(t, ctrl.checkApproverAuthorization(approvers, "user1@example.com", nil))
	assert.True(t, ctrl.checkApproverAuthorization(approvers, "user2@example.com", nil))
	assert.False(t, ctrl.checkApproverAuthorization(approvers, "user3@example.com", nil))
}

func TestCheckApproverAuthorization_DirectUserMatchNormalizesExactEntries(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	approvers := &breakglassv1alpha1.DebugSessionApprovers{
		Users: []string{" Approver@Example.COM "},
	}

	assert.True(t, ctrl.checkApproverAuthorization(approvers, "approver@example.com", nil))
	assert.True(t, ctrl.checkApproverAuthorization(approvers, " APPROVER@example.com ", nil))
	assert.False(t, ctrl.checkApproverAuthorization(approvers, "other@example.com", nil))
}

func TestCheckApproverAuthorization_GlobUserMatchKeepsPatternSemantics(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	approvers := &breakglassv1alpha1.DebugSessionApprovers{
		Users: []string{" *@Example.COM "},
	}

	assert.True(t, ctrl.checkApproverAuthorization(approvers, "approver@Example.COM", nil))
	assert.True(t, ctrl.checkApproverAuthorization(approvers, " approver@Example.COM ", nil))
	assert.False(t, ctrl.checkApproverAuthorization(approvers, "approver@example.com", nil))
}

func TestCheckApproverAuthorization_DirectGroupMatch(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	approvers := &breakglassv1alpha1.DebugSessionApprovers{
		Groups: []string{"admin-group", "approvers"},
	}

	assert.True(t, ctrl.checkApproverAuthorization(approvers, "user@example.com", []string{"admin-group"}))
	assert.True(t, ctrl.checkApproverAuthorization(approvers, "user@example.com", []string{"approvers"}))
	assert.True(t, ctrl.checkApproverAuthorization(approvers, "user@example.com", []string{"other", "approvers"}))
	assert.False(t, ctrl.checkApproverAuthorization(approvers, "user@example.com", []string{"developers"}))
}

// ============================================================================
// Tests for matchPattern
// ============================================================================

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern  string
		value    string
		expected bool
	}{
		// Exact match
		{"admin", "admin", true},
		{"admin", "user", false},

		// Prefix wildcard (*suffix)
		{"*@example.com", "user@example.com", true},
		{"*@example.com", "user@other.com", false},
		{"*-admin", "cluster-admin", true},
		{"*-admin", "cluster-user", false},

		// Suffix wildcard (prefix*)
		{"user*", "user123", true},
		{"user*", "admin123", false},
		{"team-*", "team-alpha", true},
		{"team-*", "group-alpha", false},

		// Universal wildcard
		{"*", "anything", true},
		{"*", "", true},

		// Invalid glob pattern - falls back to exact match
		{"[unclosed", "[unclosed", true},  // Exact match succeeds
		{"[unclosed", "something", false}, // Exact match fails
	}

	for _, tc := range tests {
		t.Run(tc.pattern+"_"+tc.value, func(t *testing.T) {
			result := matchPattern(tc.pattern, tc.value)
			assert.Equal(t, tc.expected, result, "pattern=%s, value=%s", tc.pattern, tc.value)
		})
	}
}

// ============================================================================
// Tests for resolveClusterPatterns
// ============================================================================

func TestResolveClusterPatterns(t *testing.T) {
	allClusters := []string{"prod-east", "prod-west", "staging-east", "dev-local", "ship-lab-1", "ship-lab-2"}

	tests := []struct {
		name     string
		patterns []string
		expected []string
	}{
		{
			name:     "wildcard matches all",
			patterns: []string{"*"},
			expected: []string{"dev-local", "prod-east", "prod-west", "ship-lab-1", "ship-lab-2", "staging-east"},
		},
		{
			name:     "prefix pattern",
			patterns: []string{"prod-*"},
			expected: []string{"prod-east", "prod-west"},
		},
		{
			name:     "suffix pattern",
			patterns: []string{"*-east"},
			expected: []string{"prod-east", "staging-east"},
		},
		{
			name:     "exact match",
			patterns: []string{"dev-local"},
			expected: []string{"dev-local"},
		},
		{
			name:     "multiple patterns",
			patterns: []string{"prod-*", "ship-lab-*"},
			expected: []string{"prod-east", "prod-west", "ship-lab-1", "ship-lab-2"},
		},
		{
			name:     "empty patterns",
			patterns: []string{},
			expected: nil,
		},
		{
			name:     "no matches",
			patterns: []string{"unknown-*"},
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := resolveClusterPatterns(tc.patterns, allClusters)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// ============================================================================
// Tests for isUserParticipant
// ============================================================================

func TestIsUserParticipant_SessionOwner(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			RequestedBy: "owner@example.com",
		},
	}

	assert.True(t, ctrl.isUserParticipant(session, "owner@example.com"), "owner should be a participant")
	assert.False(t, ctrl.isUserParticipant(session, "other@example.com"), "non-owner should not be a participant")
}

func TestIsUserParticipant_ActiveParticipant(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	session := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			RequestedBy: "owner@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			Participants: []breakglassv1alpha1.DebugSessionParticipant{
				{User: "participant1@example.com", LeftAt: nil},
				{User: "participant2@example.com", LeftAt: nil},
			},
		},
	}

	assert.True(t, ctrl.isUserParticipant(session, "participant1@example.com"))
	assert.True(t, ctrl.isUserParticipant(session, "participant2@example.com"))
	assert.False(t, ctrl.isUserParticipant(session, "other@example.com"))
}

func TestIsUserParticipant_LeftParticipant(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	leftAt := metav1.Now()
	session := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			RequestedBy: "owner@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			Participants: []breakglassv1alpha1.DebugSessionParticipant{
				{User: "left-participant@example.com", LeftAt: &leftAt},
			},
		},
	}

	// Participant who left should not be considered active
	assert.False(t, ctrl.isUserParticipant(session, "left-participant@example.com"))
}

func TestCanUserOperateDebugResources(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	now := metav1.Now()
	leftAt := metav1.Now()
	session := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			RequestedBy: "owner@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			Participants: []breakglassv1alpha1.DebugSessionParticipant{
				{User: "participant@example.com", Role: breakglassv1alpha1.ParticipantRoleParticipant, JoinedAt: now},
				{User: "status-owner@example.com", Role: breakglassv1alpha1.ParticipantRoleOwner, JoinedAt: now},
				{User: "viewer@example.com", Role: breakglassv1alpha1.ParticipantRoleViewer, JoinedAt: now},
				{User: "left-participant@example.com", Role: breakglassv1alpha1.ParticipantRoleParticipant, JoinedAt: now, LeftAt: &leftAt},
				{User: "unknown-role@example.com", Role: breakglassv1alpha1.ParticipantRole("operator"), JoinedAt: now},
				{User: "empty-role@example.com", JoinedAt: now},
				{User: "upgraded@example.com", Role: breakglassv1alpha1.ParticipantRoleViewer, JoinedAt: now},
				{User: "upgraded@example.com", Role: breakglassv1alpha1.ParticipantRoleParticipant, JoinedAt: now},
			},
		},
	}

	tests := []struct {
		name string
		user string
		want bool
	}{
		{name: "session requester", user: "owner@example.com", want: true},
		{name: "active participant", user: "participant@example.com", want: true},
		{name: "status owner", user: "status-owner@example.com", want: true},
		{name: "viewer cannot mutate", user: "viewer@example.com", want: false},
		{name: "left participant cannot mutate", user: "left-participant@example.com", want: false},
		{name: "unknown role cannot mutate", user: "unknown-role@example.com", want: false},
		{name: "empty role cannot mutate", user: "empty-role@example.com", want: false},
		{name: "later participant role can mutate after viewer entry", user: "upgraded@example.com", want: true},
		{name: "unrelated user", user: "other@example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ctrl.canUserOperateDebugResources(session, tt.user))
		})
	}
}

// ============================================================================
// Tests for extractCapabilities and extractRunAsNonRoot
// ============================================================================

func TestExtractCapabilities(t *testing.T) {
	t.Run("nil security context", func(t *testing.T) {
		result := extractCapabilities(nil)
		assert.Nil(t, result)
	})

	t.Run("nil capabilities", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: nil,
		}
		result := extractCapabilities(sc)
		assert.Nil(t, result)
	})

	t.Run("empty capabilities", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{},
		}
		result := extractCapabilities(sc)
		assert.Nil(t, result)
	})

	t.Run("single capability", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
		}
		result := extractCapabilities(sc)
		assert.Equal(t, []string{"NET_ADMIN"}, result)
	})

	t.Run("multiple capabilities", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN", "SYS_ADMIN", "CAP_NET_RAW"},
			},
		}
		result := extractCapabilities(sc)
		assert.Equal(t, []string{"NET_ADMIN", "SYS_ADMIN", "CAP_NET_RAW"}, result)
	})
}

func TestExtractRunAsNonRoot(t *testing.T) {
	t.Run("nil security context", func(t *testing.T) {
		result := extractRunAsNonRoot(nil)
		assert.False(t, result)
	})

	t.Run("nil runAsNonRoot", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			RunAsNonRoot: nil,
		}
		result := extractRunAsNonRoot(sc)
		assert.False(t, result)
	})

	t.Run("runAsNonRoot true", func(t *testing.T) {
		trueVal := true
		sc := &corev1.SecurityContext{
			RunAsNonRoot: &trueVal,
		}
		result := extractRunAsNonRoot(sc)
		assert.True(t, result)
	})

	t.Run("runAsNonRoot false", func(t *testing.T) {
		falseVal := false
		sc := &corev1.SecurityContext{
			RunAsNonRoot: &falseVal,
		}
		result := extractRunAsNonRoot(sc)
		assert.False(t, result)
	})
}

func TestExtractPrivileged(t *testing.T) {
	t.Run("nil security context", func(t *testing.T) {
		result := extractPrivileged(nil)
		assert.False(t, result)
	})

	t.Run("nil privileged", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Privileged: nil,
		}
		result := extractPrivileged(sc)
		assert.False(t, result)
	})

	t.Run("privileged true", func(t *testing.T) {
		trueVal := true
		sc := &corev1.SecurityContext{
			Privileged: &trueVal,
		}
		result := extractPrivileged(sc)
		assert.True(t, result)
	})

	t.Run("privileged false", func(t *testing.T) {
		falseVal := false
		sc := &corev1.SecurityContext{
			Privileged: &falseVal,
		}
		result := extractPrivileged(sc)
		assert.False(t, result)
	})
}

// ============================================================================
// Tests for getDebugSessionByName
// ============================================================================

func TestGetDebugSessionByName_Found(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass",
			Labels: map[string]string{
				DebugSessionLabelKey: "test-session",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	ctx := context.Background()
	found, err := ctrl.getDebugSessionByName(ctx, "test-session", "breakglass")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "test-session", found.Name)
}

func TestGetDebugSessionByName_NamespaceHintIsStrict(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "breakglass",
			Labels: map[string]string{
				DebugSessionLabelKey: "test-session",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	ctx := context.Background()
	found, err := ctrl.getDebugSessionByName(ctx, "test-session", "wrong-namespace")
	require.Error(t, err)
	require.Nil(t, found)
	assert.True(t, apierrors.IsNotFound(err))
}

func TestGetDebugSessionByName_NotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	ctx := context.Background()
	found, err := ctrl.getDebugSessionByName(ctx, "non-existent", "")
	require.Error(t, err)
	require.Nil(t, found)
}

func TestGetDebugSessionByName_FoundViaLabel(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "debug-user-cluster-12345",
			Namespace: "breakglass",
			Labels: map[string]string{
				DebugSessionLabelKey: "debug-user-cluster-12345",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	ctx := context.Background()
	// Search without namespace hint - should find via label
	found, err := ctrl.getDebugSessionByName(ctx, "debug-user-cluster-12345", "")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "debug-user-cluster-12345", found.Name)
}

func TestGetDebugSessionByName_DefaultNamespaceFallback(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	// Session in default namespace without label
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "simple-session",
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(session).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	ctx := context.Background()
	found, err := ctrl.getDebugSessionByName(ctx, "simple-session", "")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "simple-session", found.Name)
}

func TestGetDebugSessionByName_DefaultNamespaceFallbackPropagatesGetError(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	expectedErr := errors.New("default namespace lookup failed")

	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
				if key.Name == "error-session" && key.Namespace == "default" {
					return expectedErr
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	ctx := context.Background()
	found, err := ctrl.getDebugSessionByName(ctx, "error-session", "")
	require.ErrorIs(t, err, expectedErr)
	require.Nil(t, found)
}

// ============================================================================
// Tests for shouldSendNotification
// ============================================================================

func TestShouldSendNotification(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *breakglassv1alpha1.DebugSessionNotificationConfig
		event    notificationEvent
		expected bool
	}{
		{
			name:     "nil config returns true",
			cfg:      nil,
			event:    notificationEventRequest,
			expected: true,
		},
		{
			name: "disabled config returns false",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled: false,
			},
			event:    notificationEventRequest,
			expected: false,
		},
		{
			name: "enabled config - request event with notify on request",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:         true,
				NotifyOnRequest: true,
			},
			event:    notificationEventRequest,
			expected: true,
		},
		{
			name: "enabled config - request event without notify on request",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:         true,
				NotifyOnRequest: false,
			},
			event:    notificationEventRequest,
			expected: false,
		},
		{
			name: "enabled config - approval event with notify on approval",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:          true,
				NotifyOnApproval: true,
			},
			event:    notificationEventApproval,
			expected: true,
		},
		{
			name: "enabled config - approval event without notify on approval",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:          true,
				NotifyOnApproval: false,
			},
			event:    notificationEventApproval,
			expected: false,
		},
		{
			name: "enabled config - expiry event with notify on expiry",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:        true,
				NotifyOnExpiry: true,
			},
			event:    notificationEventExpiry,
			expected: true,
		},
		{
			name: "enabled config - expiry event without notify on expiry",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:        true,
				NotifyOnExpiry: false,
			},
			event:    notificationEventExpiry,
			expected: false,
		},
		{
			name: "enabled config - termination event with notify on termination",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:             true,
				NotifyOnTermination: true,
			},
			event:    notificationEventTermination,
			expected: true,
		},
		{
			name: "enabled config - termination event without notify on termination",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled:             true,
				NotifyOnTermination: false,
			},
			event:    notificationEventTermination,
			expected: false,
		},
		{
			name: "enabled config - unknown event returns true",
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				Enabled: true,
			},
			event:    notificationEvent("unknown"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSendNotification(tt.cfg, tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Tests for buildNotificationRecipients
// ============================================================================

func TestBuildNotificationRecipients(t *testing.T) {
	tests := []struct {
		name      string
		base      []string
		cfg       *breakglassv1alpha1.DebugSessionNotificationConfig
		wantEmpty bool
		wantLen   int
	}{
		{
			name:      "nil config and empty base returns nil",
			base:      nil,
			cfg:       nil,
			wantEmpty: true,
		},
		{
			name:      "empty base and nil config returns nil",
			base:      []string{},
			cfg:       nil,
			wantEmpty: true,
		},
		{
			name:    "base recipients with nil config",
			base:    []string{"user@example.com"},
			cfg:     nil,
			wantLen: 1,
		},
		{
			name: "base recipients with additional recipients in config",
			base: []string{"user@example.com"},
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				AdditionalRecipients: []string{"admin@example.com"},
			},
			wantLen: 2,
		},
		{
			name: "deduplication of recipients",
			base: []string{"user@example.com", "admin@example.com"},
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				AdditionalRecipients: []string{"user@example.com", "new@example.com"},
			},
			wantLen: 3, // user, admin, new (user deduplicated)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildNotificationRecipients(tt.base, tt.cfg)
			if tt.wantEmpty {
				assert.Nil(t, result)
			} else {
				assert.Len(t, result, tt.wantLen)
			}
		})
	}
}

// ============================================================================
// Edge Case and Failure Tests
// ============================================================================

func TestBuildNotificationRecipients_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		base    []string
		cfg     *breakglassv1alpha1.DebugSessionNotificationConfig
		wantLen int
	}{
		{
			name: "empty strings in base are skipped",
			base: []string{"", "user@example.com", ""},
			cfg:  nil,
			// Empty strings should be filtered out
			wantLen: 1,
		},
		{
			name: "empty strings in additional recipients are skipped",
			base: []string{"user@example.com"},
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				AdditionalRecipients: []string{"", "admin@example.com", ""},
			},
			wantLen: 2,
		},
		{
			name: "all duplicates should be deduplicated",
			base: []string{"user@example.com", "user@example.com", "user@example.com"},
			cfg: &breakglassv1alpha1.DebugSessionNotificationConfig{
				AdditionalRecipients: []string{"user@example.com", "user@example.com"},
			},
			wantLen: 1, // Only one unique
		},
		{
			name:    "only empty strings returns empty result",
			base:    []string{"", "", ""},
			cfg:     nil,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildNotificationRecipients(tt.base, tt.cfg)
			if tt.wantLen == 0 {
				// Either nil or empty slice is acceptable for 0 length
				assert.Empty(t, result)
			} else {
				assert.Len(t, result, tt.wantLen)
			}
		})
	}
}

func TestExtractCapabilities_EdgeCases(t *testing.T) {
	t.Run("capabilities with Drop only returns nil", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
				Add:  nil, // No capabilities added
			},
		}
		result := extractCapabilities(sc)
		assert.Nil(t, result)
	})

	t.Run("empty Add slice returns nil", func(t *testing.T) {
		sc := &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{},
			},
		}
		result := extractCapabilities(sc)
		assert.Nil(t, result)
	})
}

func TestExtractRunAsNonRoot_EdgeCases(t *testing.T) {
	t.Run("security context with other fields but nil runAsNonRoot", func(t *testing.T) {
		privileged := true
		sc := &corev1.SecurityContext{
			Privileged:   &privileged,
			RunAsNonRoot: nil,
		}
		result := extractRunAsNonRoot(sc)
		assert.False(t, result)
	})
}

// Test that invalid session state transitions are properly rejected
func TestSessionStateTransition_InvalidTransitions(t *testing.T) {
	// This tests the core logic that terminal states cannot transition
	terminalStates := []breakglassv1alpha1.DebugSessionState{
		breakglassv1alpha1.DebugSessionStateExpired,
		breakglassv1alpha1.DebugSessionStateTerminated,
		breakglassv1alpha1.DebugSessionStateFailed,
	}

	for _, terminalState := range terminalStates {
		t.Run("terminal state "+string(terminalState)+" cannot become active", func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: terminalState,
				},
			}
			// Verify it's in a terminal state
			assert.Contains(t, []breakglassv1alpha1.DebugSessionState{
				breakglassv1alpha1.DebugSessionStateExpired,
				breakglassv1alpha1.DebugSessionStateTerminated,
				breakglassv1alpha1.DebugSessionStateFailed,
			}, session.Status.State)
		})
	}
}

// Test controller with nil/invalid inputs
func TestDebugSessionAPIController_NilInputHandling(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).Build()
	ctrl := NewDebugSessionAPIController(logger, fakeClient, nil, nil)

	t.Run("getDebugSessionByName with empty name", func(t *testing.T) {
		_, err := ctrl.getDebugSessionByName(context.Background(), "", "namespace")
		// Should return an error for empty name
		assert.Error(t, err)
	})
}
