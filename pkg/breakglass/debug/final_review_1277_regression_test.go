package debug

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	bg "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ssa "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	core "github.com/telekom/k8s-breakglass/pkg/breakglass"
	v1 "k8s.io/api/core/v1"
	ext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"net/http/httptest"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"strings"
	"testing"
	"time"
)

func TestFinalReviewIdentitySerialization(t *testing.T) {
	if ssa.AllowedPodRefFrom(&bg.AllowedPodRef{UID: "pod-uid"}).UID == nil {
		t.Error("allowed pod UID omitted")
	}
	if ssa.CopiedPodRefFrom(&bg.CopiedPodRef{CopyUID: "copy-uid"}).CopyUID == nil {
		t.Error("CopyUID omitted")
	}
	if ssa.DebugSessionParticipantFrom(&bg.DebugSessionParticipant{IdentityProviderName: "idp", IdentityProviderIssuer: "issuer"}).IdentityProviderIssuer == nil {
		t.Error("participant issuer omitted")
	}
}
func TestFinalReviewCaptureExactUID(t *testing.T) {
	s := runtime.NewScheme()
	_ = v1.AddToScheme(s)
	original := &v1.Pod{ObjectMeta: meta.ObjectMeta{Name: "pod", Namespace: "ns", UID: "original"}}
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
	_ = bg.AddToScheme(s)
	expiry := meta.NewTime(time.Now().Add(time.Hour))
	ds := &bg.DebugSession{ObjectMeta: meta.ObjectMeta{Name: "session", Namespace: "ns", UID: "uid"}, Spec: bg.DebugSessionSpec{Cluster: "spoke", RequestedBy: "alice", IdentityProviderName: "trusted", IdentityProviderIssuer: "https://trusted"}, Status: bg.DebugSessionStatus{State: bg.DebugSessionStateActive, ExpiresAt: &expiry}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(ds).Build()
	h := NewKubectlDebugHandler(cl, nil).withIdentity(debugSessionReadIdentity{username: "alice", provider: "other", issuer: "https://other"})
	if _, err := h.liveSessionForMutation(context.Background(), ds, "alice"); err == nil {
		t.Fatal("mutation fence accepted wrong issuer")
	}
}
func TestFinalReviewApplyUIDFence(t *testing.T) {
	s := runtime.NewScheme()
	_ = bg.AddToScheme(s)
	live := &bg.DebugSession{ObjectMeta: meta.ObjectMeta{Name: "session", Namespace: "ns", UID: "replacement", ResourceVersion: "1"}, Status: bg.DebugSessionStatus{State: bg.DebugSessionStatePending}}
	cl := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&bg.DebugSession{}).WithObjects(live).Build()
	stale := live.DeepCopy()
	stale.UID = "original"
	stale.Status.Message = "stale owner write"
	if err := core.ApplyDebugSessionStatus(context.Background(), cl, stale); err == nil {
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
	_ = bg.AddToScheme(s)
	live := &bg.DebugSession{ObjectMeta: meta.ObjectMeta{Name: "session", Namespace: "ns", UID: "uid", ResourceVersion: "1"}, Status: bg.DebugSessionStatus{State: bg.DebugSessionStatePending, ResolvedBindingSnapshotCaptured: true}}
	cl := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&bg.DebugSession{}).WithObjects(live).Build()
	desired := live.DeepCopy()
	desired.Status.ResolvedBindingSpec = &ext.JSON{Raw: []byte(`{"displayName":"changed"}`)}
	if err := core.ApplyDebugSessionStatus(context.Background(), cl, desired); err == nil {
		t.Fatal("status apply changed approved no-binding decision")
	}
}
