package v1alpha1

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBreakglassEscalation_ValidateCreate_MissingFields(t *testing.T) {
	be := &BreakglassEscalation{}
	_, err := be.ValidateCreate(context.Background(), be)
	if err == nil {
		t.Fatalf("expected ValidateCreate to fail when required fields missing")
	}
}

func TestBreakglassEscalation_ValidateCreate_Success(t *testing.T) {
	be := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-1"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "some-group",
			Allowed:        BreakglassEscalationAllowed{Clusters: []string{"cluster-a"}},
			Approvers:      BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
		},
	}
	_, err := be.ValidateCreate(context.Background(), be)
	if err != nil {
		t.Fatalf("expected ValidateCreate to succeed, got %v", err)
	}
}

func TestBreakglassEscalation_ValidateUpdate_Immutable(t *testing.T) {
	old := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-2"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "g1",
			Allowed:        BreakglassEscalationAllowed{Clusters: []string{"c1"}},
			Approvers:      BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
		},
	}
	modified := old.DeepCopy()
	modified.Spec.EscalatedGroup = "g2"
	// spec immutability no longer enforced; update should succeed
	_, err := modified.ValidateUpdate(context.Background(), old, modified)
	if err != nil {
		t.Fatalf("expected ValidateUpdate to succeed when spec changed, got %v", err)
	}
	_, err = old.ValidateUpdate(context.Background(), old, old)
	if err != nil {
		t.Fatalf("expected ValidateUpdate to succeed when spec unchanged, got %v", err)
	}
}
