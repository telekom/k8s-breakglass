// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestSpokeWriteRejectsOverflowingLeaseEpochBeforeIO(t *testing.T) {
	object := &breakglassv1alpha1.DebugSessionArtifact{}
	object.Spec.OperationEpoch = math.MaxInt64 + 1
	err := (&Reconciler{}).validateSpokeWrite(context.Background(), object, nil, nil, nil)
	require.ErrorContains(t, err, "epoch exceeds lease range")
}
