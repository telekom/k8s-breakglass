package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestFindNewEphemeralContainers(t *testing.T) {
	tests := []struct {
		name     string
		old      []corev1.EphemeralContainer
		new      []corev1.EphemeralContainer
		expected []corev1.EphemeralContainer
	}{
		{
			name:     "no containers",
			old:      nil,
			new:      nil,
			expected: []corev1.EphemeralContainer{},
		},
		{
			name: "empty old, one new",
			old:  nil,
			new: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
			},
			expected: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
			},
		},
		{
			name: "same containers, no new",
			old: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
			},
			new: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
			},
			expected: []corev1.EphemeralContainer{},
		},
		{
			name: "one new container added",
			old: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
			},
			new: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-2", Image: "alpine"}},
			},
			expected: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-2", Image: "alpine"}},
			},
		},
		{
			name: "multiple new containers",
			old:  []corev1.EphemeralContainer{},
			new: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-2", Image: "alpine"}},
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-3", Image: "ubuntu"}},
			},
			expected: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1", Image: "busybox"}},
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-2", Image: "alpine"}},
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-3", Image: "ubuntu"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findNewEphemeralContainers(tt.old, tt.new)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCapsToStrings(t *testing.T) {
	tests := []struct {
		name     string
		sc       *corev1.SecurityContext
		expected []string
	}{
		{
			name:     "nil security context",
			sc:       nil,
			expected: nil,
		},
		{
			name:     "nil capabilities",
			sc:       &corev1.SecurityContext{},
			expected: nil,
		},
		{
			name: "empty capabilities",
			sc: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{},
			},
			expected: []string{},
		},
		{
			name: "single capability",
			sc: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"NET_ADMIN"},
				},
			},
			expected: []string{"NET_ADMIN"},
		},
		{
			name: "multiple capabilities",
			sc: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"NET_ADMIN", "SYS_PTRACE", "SYS_ADMIN"},
				},
			},
			expected: []string{"NET_ADMIN", "SYS_PTRACE", "SYS_ADMIN"},
		},
		{
			name: "drop capabilities are ignored",
			sc: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add:  []corev1.Capability{"NET_ADMIN"},
					Drop: []corev1.Capability{"ALL"},
				},
			},
			expected: []string{"NET_ADMIN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := capsToStrings(tt.sc)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsRunAsNonRoot(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name     string
		sc       *corev1.SecurityContext
		expected bool
	}{
		{
			name:     "nil security context",
			sc:       nil,
			expected: false,
		},
		{
			name:     "nil RunAsNonRoot",
			sc:       &corev1.SecurityContext{},
			expected: false,
		},
		{
			name: "RunAsNonRoot true",
			sc: &corev1.SecurityContext{
				RunAsNonRoot: &trueVal,
			},
			expected: true,
		},
		{
			name: "RunAsNonRoot false",
			sc: &corev1.SecurityContext{
				RunAsNonRoot: &falseVal,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRunAsNonRoot(tt.sc)
			assert.Equal(t, tt.expected, result)
		})
	}
}
