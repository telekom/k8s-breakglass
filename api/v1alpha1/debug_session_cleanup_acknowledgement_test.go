// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const ackList = `[{"apiVersion":"policies.kyverno.io/v1","kind":"PolicyException","namespace":"ns","name":"x","uid":"u"}]`

func ackSession(annotations map[string]string) *DebugSession {
	return &DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "ns", Annotations: annotations},
		Spec:       DebugSessionSpec{Cluster: "c", TemplateRef: "t", RequestedBy: "requester@example.com"},
	}
}

func asUser(user string) context.Context {
	return admission.NewContextWithRequest(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UserInfo: authenticationv1.UserInfo{Username: user, Groups: []string{"g"}},
	}})
}

// allowSAR grants acknowledge-cleanup to the listed users and records reviews.
func allowSAR(t *testing.T, allowed ...string) *[]authorizationv1.SubjectAccessReview {
	t.Helper()
	var reviews []authorizationv1.SubjectAccessReview
	original := subjectAccessReviewer
	t.Cleanup(func() { subjectAccessReviewer = original })
	subjectAccessReviewer = func(_ context.Context, sar *authorizationv1.SubjectAccessReview) error {
		reviews = append(reviews, *sar)
		for _, user := range allowed {
			if sar.Spec.User == user {
				sar.Status.Allowed = true
			}
		}
		return nil
	}
	return &reviews
}

func TestCleanupAcknowledgementRejectedOnCreate(t *testing.T) {
	for _, key := range DebugSessionCleanupAcknowledgementAnnotations {
		_, err := (&DebugSession{}).ValidateCreate(asUser("operator"), ackSession(map[string]string{key: "x"}))
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), "authorized update")
	}
}

func TestCleanupAcknowledgementRejectedInBindingAnnotations(t *testing.T) {
	binding := &DebugSessionClusterBinding{Spec: DebugSessionClusterBindingSpec{
		TemplateRef: &TemplateReference{Name: "t"}, Clusters: []string{"c"},
		Annotations: map[string]string{DebugSessionCleanupAcknowledgedAbsentAnnotation: ackList},
	}}
	result := ValidateDebugSessionClusterBinding(binding)
	require.False(t, result.IsValid())
	assert.Contains(t, result.Errors.ToAggregate().Error(), "spec.annotations[breakglass.t-caas.telekom.com/cleanup-acknowledged-absent]")
}

func TestCleanupAcknowledgementUpdateAuthorization(t *testing.T) {
	ack := func(by string) map[string]string {
		return map[string]string{DebugSessionCleanupAcknowledgedAbsentAnnotation: ackList, DebugSessionCleanupAcknowledgedByAnnotation: by}
	}
	old := ackSession(nil)

	t.Run("operator holding the verb", func(t *testing.T) {
		reviews := allowSAR(t, "operator")
		_, err := (&DebugSession{}).ValidateUpdate(asUser("operator"), old, ackSession(ack("operator")))
		require.NoError(t, err)
		require.Len(t, *reviews, 1)
		attrs := (*reviews)[0].Spec.ResourceAttributes
		assert.Equal(t, DebugSessionCleanupAcknowledgeVerb, attrs.Verb)
		assert.Equal(t, "debugsessions", attrs.Resource)
		assert.Equal(t, GroupVersion.Group, attrs.Group)
		assert.Equal(t, "ns", attrs.Namespace)
		assert.Equal(t, "s", attrs.Name)
	})
	t.Run("requester without the verb cannot self-acknowledge", func(t *testing.T) {
		allowSAR(t, "operator")
		_, err := (&DebugSession{}).ValidateUpdate(asUser("requester@example.com"), old, ackSession(ack("requester@example.com")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "may not acknowledge-cleanup")
	})
	t.Run("acknowledged-by must be the requesting user", func(t *testing.T) {
		reviews := allowSAR(t, "operator")
		_, err := (&DebugSession{}).ValidateUpdate(asUser("operator"), old, ackSession(ack("someone-else")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), `must equal the requesting user "operator"`)
		assert.Empty(t, *reviews)
	})
	t.Run("metadata without the list", func(t *testing.T) {
		allowSAR(t, "operator")
		_, err := (&DebugSession{}).ValidateUpdate(asUser("operator"), old, ackSession(map[string]string{DebugSessionCleanupAcknowledgedByAnnotation: "operator"}))
		require.Error(t, err)
	})
	t.Run("no admission request", func(t *testing.T) {
		allowSAR(t, "operator")
		_, err := (&DebugSession{}).ValidateUpdate(context.Background(), old, ackSession(ack("operator")))
		require.Error(t, err)
	})
	t.Run("SAR failure fails closed", func(t *testing.T) {
		original := subjectAccessReviewer
		t.Cleanup(func() { subjectAccessReviewer = original })
		subjectAccessReviewer = func(context.Context, *authorizationv1.SubjectAccessReview) error {
			return errors.New("apiserver unavailable")
		}
		_, err := (&DebugSession{}).ValidateUpdate(asUser("operator"), old, ackSession(ack("operator")))
		require.Error(t, err)
	})
	t.Run("unchanged or removed acknowledgement needs no authorization", func(t *testing.T) {
		reviews := allowSAR(t)
		existing := ackSession(ack("operator"))
		_, err := (&DebugSession{}).ValidateUpdate(asUser("controller"), existing, existing.DeepCopy())
		require.NoError(t, err)
		_, err = (&DebugSession{}).ValidateUpdate(asUser("anyone"), existing, ackSession(nil))
		require.NoError(t, err)
		assert.Empty(t, *reviews)
	})
}

func TestCleanupAcknowledgementPartialRemovalNeedsAuthorization(t *testing.T) {
	full := ackSession(map[string]string{
		DebugSessionCleanupAcknowledgedAbsentAnnotation: ackList, DebugSessionCleanupAcknowledgedByAnnotation: "operator",
		DebugSessionCleanupAcknowledgedReasonAnnotation: "CHG-1",
	})
	partial := full.DeepCopy()
	delete(partial.Annotations, DebugSessionCleanupAcknowledgedByAnnotation)
	reviews := allowSAR(t, "operator")
	_, err := (&DebugSession{}).ValidateUpdate(asUser("requester@example.com"), full, partial)
	require.Error(t, err, "removing only acknowledged-by would forge an actorless acknowledgement")

	reasonOnly := full.DeepCopy()
	delete(reasonOnly.Annotations, DebugSessionCleanupAcknowledgedReasonAnnotation)
	_, err = (&DebugSession{}).ValidateUpdate(asUser("requester@example.com"), full, reasonOnly)
	require.Error(t, err, "any partial change needs the verb")
	assert.Empty(t, *reviews, "acknowledged-by mismatch is rejected before the SubjectAccessReview")

	_, err = (&DebugSession{}).ValidateUpdate(asUser("requester@example.com"), full, ackSession(nil))
	require.NoError(t, err, "removing the whole acknowledgement is allowed")
}
