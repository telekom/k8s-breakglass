package debug

import (
	"testing"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDebugSessionIdleDeadlineUsesServerActivity(t *testing.T) {
	now := time.Now().UTC()
	activity := metav1.NewTime(now)
	ds := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{
		LastActivity:     &activity,
		ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "5m"}},
	}}
	deadline, ok := debugSessionIdleDeadline(ds)
	if !ok || !deadline.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("deadline=%v, ok=%v", deadline, ok)
	}
}

func TestStampDebugSessionRetentionPreservesConfiguredDuration(t *testing.T) {
	status := &breakglassv1alpha1.DebugSessionStatus{}
	stampDebugSessionRetention(status, &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{RetainFor: "2h"}})
	if status.RetainedUntil == nil || time.Until(status.RetainedUntil.Time) < time.Hour {
		t.Fatalf("retention not stamped: %#v", status.RetainedUntil)
	}
}
