package debug

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestEffectiveDebugSessionConstraints(t *testing.T) {
	allowRenewal := true
	maxRenewals := int32(4)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
				AllowRenewal:    &allowRenewal,
				MaxRenewals:     &maxRenewals,
			},
		},
	}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration: "2h",
			},
		},
	}

	constraints := effectiveDebugSessionConstraints(template, binding)

	require.NotNil(t, constraints)
	assert.Equal(t, "2h", constraints.MaxDuration)
	assert.Equal(t, "1h", constraints.DefaultDuration)
	require.NotNil(t, constraints.AllowRenewal)
	assert.True(t, *constraints.AllowRenewal)
	require.NotNil(t, constraints.MaxRenewals)
	assert.Equal(t, int32(4), *constraints.MaxRenewals)
}

func TestValidateRequestedDebugSessionDuration(t *testing.T) {
	constraints := &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "2h"}

	tests := []struct {
		name        string
		requested   string
		wantErr     bool
		errContains string
	}{
		{name: "empty is allowed", requested: ""},
		{name: "within max", requested: "90m"},
		{name: "zero rejected", requested: "0", wantErr: true, errContains: "positive"},
		{name: "negative rejected", requested: "-1h", wantErr: true, errContains: "positive"},
		{name: "above max rejected", requested: "3h", wantErr: true, errContains: "exceeds maximum duration 2h"},
		{name: "invalid rejected", requested: "not-a-duration", wantErr: true, errContains: "invalid requestedDuration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequestedDebugSessionDuration(tt.requested, constraints)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
		})
	}

	maxDuration, maxLabel, err := maxDebugSessionDuration(constraints)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Hour, maxDuration)
	assert.Equal(t, "2h", maxLabel)
}
