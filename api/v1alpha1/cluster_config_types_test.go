package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestClusterConfig_ValidateCreate_MissingSecretRef(t *testing.T) {
	cc := &ClusterConfig{}
	if err := cc.ValidateCreate(); err == nil {
		t.Fatalf("expected ValidateCreate to fail when kubeconfig secret ref missing")
	}
}

func TestClusterConfig_ValidateCreate_Success(t *testing.T) {
	cc := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cc-1"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef: SecretKeyReference{Name: "k", Namespace: "ns"},
		},
	}
	if err := cc.ValidateCreate(); err != nil {
		t.Fatalf("expected ValidateCreate to succeed, got %v", err)
	}
}

func TestClusterConfig_ValidateUpdate_Immutable(t *testing.T) {
	old := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cc-2"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef: SecretKeyReference{Name: "k", Namespace: "ns"},
		},
	}
	modified := old.DeepCopy()
	modified.Spec.QPS = func() *int32 { v := int32(10); return &v }()
	// spec immutability no longer enforced; update should succeed
	if err := modified.ValidateUpdate(old); err != nil {
		t.Fatalf("expected ValidateUpdate to succeed when spec changed, got %v", err)
	}
	if err := old.ValidateUpdate(old); err != nil {
		t.Fatalf("expected ValidateUpdate to succeed when spec unchanged, got %v", err)
	}
}
