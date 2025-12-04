package v1alpha1

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCrossNamespaceNameUniqueness_BreakglassSession(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	// existing object in namespace-a (must be a valid spec)
	existing := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "same-name", Namespace: "namespace-a"},
		Spec:       BreakglassSessionSpec{Cluster: "cluster-1", User: "user@example.com", GrantedGroup: "some-group"},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(existing).Build()
	// populate package-level client for validators
	webhookClient = fakeClient
	webhookCache = nil

	// attempt create in namespace-b should be invalid due to name collision
	attempt := &BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "same-name", Namespace: "namespace-b"}, Spec: BreakglassSessionSpec{Cluster: "cluster-1", User: "user@example.com", GrantedGroup: "some-group"}}
	_, err := attempt.ValidateCreate(context.Background(), attempt)
	if err == nil {
		t.Fatalf("expected validation error due to name collision, got nil")
	}
	if !strings.Contains(err.Error(), "conflicting namespace=namespace-a") {
		t.Fatalf("expected error to reference conflicting namespace, got: %v", err)
	}
}

func TestCrossNamespaceNameUniqueness_BreakglassEscalation(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	existing := &BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "same-name", Namespace: "namespace-a"}, Spec: BreakglassEscalationSpec{EscalatedGroup: "g"}}
	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(existing).Build()
	webhookClient = fakeClient
	webhookCache = nil

	attempt := &BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "same-name", Namespace: "namespace-b"}, Spec: BreakglassEscalationSpec{EscalatedGroup: "g"}}
	_, err := attempt.ValidateCreate(context.Background(), attempt)
	if err == nil {
		t.Fatalf("expected validation error due to name collision, got nil")
	}
	if !strings.Contains(err.Error(), "conflicting namespace=namespace-a") {
		t.Fatalf("expected error to reference conflicting namespace, got: %v", err)
	}
}

func TestCrossNamespaceNameUniqueness_ClusterConfig(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	existing := &ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "same-name", Namespace: "namespace-a"}, Spec: ClusterConfigSpec{KubeconfigSecretRef: &SecretKeyReference{}}}
	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(existing).Build()
	webhookClient = fakeClient
	webhookCache = nil

	attempt := &ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "same-name", Namespace: "namespace-b"}, Spec: ClusterConfigSpec{KubeconfigSecretRef: &SecretKeyReference{}}}
	_, err := attempt.ValidateCreate(context.Background(), attempt)
	if err == nil {
		t.Fatalf("expected validation error due to name collision, got nil")
	}
	if !strings.Contains(err.Error(), "conflicting namespace=namespace-a") {
		t.Fatalf("expected error to reference conflicting namespace, got: %v", err)
	}
}
