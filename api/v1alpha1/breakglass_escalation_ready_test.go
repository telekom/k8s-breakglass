// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBreakglassEscalationIsReadyRequiresCurrentGeneration(t *testing.T) {
	ready := string(BreakglassEscalationConditionReady)
	for name, observedGeneration := range map[string]int64{"stale": 1, "current": 2} {
		t.Run(name, func(t *testing.T) {
			escalation := &BreakglassEscalation{}
			escalation.Generation = 2
			escalation.Status.Conditions = []metav1.Condition{{
				Type: ready, Status: metav1.ConditionTrue, ObservedGeneration: observedGeneration,
			}}
			assert.Equal(t, name == "current", escalation.IsReady())
		})
	}
}
