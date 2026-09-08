package debug

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ssa "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	corev1 "k8s.io/api/core/v1"
	extensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFinalReviewIdentitySerialization(t *testing.T) {
	if ssa.AllowedPodRefFrom(&breakglassv1alpha1.AllowedPodRef{UID: "pod-uid"}).UID == nil {
		t.Error("allowed pod UID omitted")
	}
	if ssa.CopiedPodRefFrom(&breakglassv1alpha1.CopiedPodRef{CopyUID: "copy-uid"}).CopyUID == nil {
		t.Error("CopyUID omitted")
	}
	if ssa.DebugSessionParticipantFrom(&breakglassv1alpha1.DebugSessionParticipant{IdentityProviderName: "idp", IdentityProviderIssuer: "issuer"}).IdentityProviderIssuer == nil {
		t.Error("participant issuer omitted")
	}
}
func TestFinalReviewCaptureExactUID(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	original := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "original"}}
	replacement := original.DeepCopy()
	replacement.UID = "replacement"
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(replacement).Build()
	got, err := captureResourceUID(context.Background(), cl, original)
	if err != nil || got != "original" {
		t.Fatalf("captured %q instead of original UID, err=%v", got, err)
	}
}
func TestFinalReviewMutationIssuerFence(t *testing.T) {
	s := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(s)
	expiry := metav1.NewTime(time.Now().Add(time.Hour))
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "uid"}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", RequestedBy: "alice", IdentityProviderName: "trusted", IdentityProviderIssuer: "https://trusted"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(ds).Build()
	h := NewKubectlDebugHandler(cl, nil).withIdentity(debugSessionReadIdentity{username: "alice", provider: "other", issuer: "https://other"})
	if _, err := h.liveSessionForMutation(context.Background(), ds, "alice"); err == nil {
		t.Fatal("mutation fence accepted wrong issuer")
	}
}
func TestFinalReviewApplyUIDFence(t *testing.T) {
	s := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(s)
	live := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "replacement", ResourceVersion: "1"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStatePending}}
	cl := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(live).Build()
	stale := live.DeepCopy()
	stale.UID = "original"
	stale.Status.Message = "stale owner write"
	if err := breakglass.ApplyDebugSessionStatus(context.Background(), cl, stale); err == nil {
		t.Fatal("status apply accepted mismatched session UID")
	}
}

func TestFinalReviewPolicyRedaction(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	respondKubectlDebugOperationError(c, kubectlDebugPolicyErrorf("configuration changed: %w", fmt.Errorf("token=secret-credential")), "failed")
	if strings.Contains(w.Body.String(), "secret-credential") {
		t.Fatalf("policy response leaked cause: %s", w.Body.String())
	}
}
func TestFinalReviewApprovedNilBindingFrozen(t *testing.T) {
	s := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(s)
	live := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "uid", ResourceVersion: "1"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStatePending, ResolvedBindingSnapshotCaptured: true}}
	cl := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(live).Build()
	desired := live.DeepCopy()
	desired.Status.ResolvedBindingSpec = &extensionsv1.JSON{Raw: []byte(`{"displayName":"changed"}`)}
	if err := breakglass.ApplyDebugSessionStatus(context.Background(), cl, desired); err == nil {
		t.Fatal("status apply changed approved no-binding decision")
	}
}
