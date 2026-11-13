// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestUnreleasedTrafficMirrorBlocksClusterConfigDeletion(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{
		TrafficMirror: &breakglassv1alpha1.TrafficMirrorStatus{OperationID: "traffic-mirror-x", CreateAttempted: true},
	}}
	require.True(t, debugSessionHasTrackedSpokeResources(session), "the mirror may still be attached before AllowedPods is set")
	session.Status.TrafficMirror.Released = true
	require.False(t, debugSessionHasTrackedSpokeResources(session))
}
