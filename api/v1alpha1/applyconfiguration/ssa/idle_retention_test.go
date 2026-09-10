// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDebugSessionStatusFromPreservesIdleRetentionAcrossSerialization(t *testing.T) {
	at := metav1.Now()
	original := &breakglassv1alpha1.DebugSessionStatus{LastActivity: &at, ActivityCount: 7, RetainedUntil: &at, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "5m", RetainFor: "24h"}}}
	encoded, err := json.Marshal(DebugSessionStatusFrom(original))
	require.NoError(t, err)
	var restored breakglassv1alpha1.DebugSessionStatus
	require.NoError(t, json.Unmarshal(encoded, &restored))
	require.EqualValues(t, 7, restored.ActivityCount)
	require.Equal(t, at.UTC().Truncate(1e9), restored.LastActivity.UTC())
	require.Equal(t, at.UTC().Truncate(1e9), restored.RetainedUntil.UTC())
	require.Equal(t, "5m", restored.ResolvedTemplate.Constraints.IdleTimeout)
	require.Equal(t, "24h", restored.ResolvedTemplate.Constraints.RetainFor)
}
