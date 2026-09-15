// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestSchedulingConstraintsRejectUnsupportedNodeGlobs(t *testing.T) {
	for _, pattern := range []string{"control-*", "node?", "node[12]"} {
		constraints := &SchedulingConstraints{DeniedNodes: []string{pattern}}
		require.NotEmpty(t, validateSchedulingConstraints(constraints, field.NewPath("spec", "schedulingConstraints")))
		require.NotEmpty(t, validateSchedulingOptions(&SchedulingOptions{Options: []SchedulingOption{{Name: "restricted", SchedulingConstraints: constraints}}}, field.NewPath("spec", "schedulingOptions")))
	}
	require.Empty(t, validateSchedulingConstraints(&SchedulingConstraints{DeniedNodes: []string{"node-a"}, DeniedNodeLabels: map[string]string{"node-role.kubernetes.io/control-plane": "*"}}, field.NewPath("spec")))
}
