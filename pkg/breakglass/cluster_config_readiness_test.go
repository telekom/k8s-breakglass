package breakglass

import (
	"testing"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsClusterConfigReady(t *testing.T) {
	tests := []struct {
		name string
		cc   *breakglassv1alpha1.ClusterConfig
		want bool
	}{
		{
			name: "nil config",
			cc:   nil,
			want: false,
		},
		{
			name: "generationless fake config without conditions remains usable",
			cc:   &breakglassv1alpha1.ClusterConfig{},
			want: true,
		},
		{
			name: "real config without conditions is not ready",
			cc: &breakglassv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Generation: 1},
			},
			want: false,
		},
		{
			name: "ready condition true",
			cc: &breakglassv1alpha1.ClusterConfig{
				Status: breakglassv1alpha1.ClusterConfigStatus{
					Conditions: []metav1.Condition{{
						Type:   string(breakglassv1alpha1.ClusterConfigConditionReady),
						Status: metav1.ConditionTrue,
					}},
				},
			},
			want: true,
		},
		{
			name: "ready condition false",
			cc: &breakglassv1alpha1.ClusterConfig{
				Status: breakglassv1alpha1.ClusterConfigStatus{
					Conditions: []metav1.Condition{{
						Type:   string(breakglassv1alpha1.ClusterConfigConditionReady),
						Status: metav1.ConditionFalse,
					}},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsClusterConfigReady(tt.cc); got != tt.want {
				t.Fatalf("IsClusterConfigReady() = %v, want %v", got, tt.want)
			}
		})
	}
}
