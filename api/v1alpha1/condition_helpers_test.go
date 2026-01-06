/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewCondition(t *testing.T) {
	cond := NewCondition("TestType", metav1.ConditionTrue, 5, "TestReason", "Test message")

	assert.Equal(t, "TestType", cond.Type)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, int64(5), cond.ObservedGeneration)
	assert.Equal(t, "TestReason", cond.Reason)
	assert.Equal(t, "Test message", cond.Message)
	assert.False(t, cond.LastTransitionTime.IsZero())
}

func TestNewReadyCondition(t *testing.T) {
	tests := []struct {
		name           string
		ready          bool
		expectedStatus metav1.ConditionStatus
	}{
		{
			name:           "ready true",
			ready:          true,
			expectedStatus: metav1.ConditionTrue,
		},
		{
			name:           "ready false",
			ready:          false,
			expectedStatus: metav1.ConditionFalse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := NewReadyCondition(3, tt.ready, "SomeReason", "Some message")

			assert.Equal(t, ConditionTypeReady, cond.Type)
			assert.Equal(t, tt.expectedStatus, cond.Status)
			assert.Equal(t, int64(3), cond.ObservedGeneration)
		})
	}
}

func TestNewReadyConditionTrue(t *testing.T) {
	cond := NewReadyConditionTrue(7, "All systems operational")

	assert.Equal(t, ConditionTypeReady, cond.Type)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, ReasonSuccess, cond.Reason)
	assert.Equal(t, "All systems operational", cond.Message)
	assert.Equal(t, int64(7), cond.ObservedGeneration)
}

func TestNewReadyConditionFalse(t *testing.T) {
	cond := NewReadyConditionFalse(2, "ValidationFailed", "Missing required field")

	assert.Equal(t, ConditionTypeReady, cond.Type)
	assert.Equal(t, metav1.ConditionFalse, cond.Status)
	assert.Equal(t, "ValidationFailed", cond.Reason)
	assert.Equal(t, "Missing required field", cond.Message)
}

func TestNewConfigValidCondition(t *testing.T) {
	validCond := NewConfigValidCondition(1, true, ReasonSuccess, "Config is valid")
	assert.Equal(t, ConditionTypeConfigValid, validCond.Type)
	assert.Equal(t, metav1.ConditionTrue, validCond.Status)

	invalidCond := NewConfigValidCondition(1, false, ReasonValidationFailed, "Invalid config")
	assert.Equal(t, ConditionTypeConfigValid, invalidCond.Type)
	assert.Equal(t, metav1.ConditionFalse, invalidCond.Status)
}

func TestNewClusterReachableCondition(t *testing.T) {
	reachableCond := NewClusterReachableCondition(1, true, ReasonSuccess, "Cluster is reachable")
	assert.Equal(t, ConditionTypeClusterReachable, reachableCond.Type)
	assert.Equal(t, metav1.ConditionTrue, reachableCond.Status)

	unreachableCond := NewClusterReachableCondition(1, false, ReasonConnectionFailed, "Connection timeout")
	assert.Equal(t, ConditionTypeClusterReachable, unreachableCond.Type)
	assert.Equal(t, metav1.ConditionFalse, unreachableCond.Status)
}

func TestNewErrorCondition(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		expectedMessage string
	}{
		{
			name:            "with error",
			err:             errors.New("connection refused"),
			expectedMessage: "connection refused",
		},
		{
			name:            "with nil error",
			err:             nil,
			expectedMessage: "Unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := NewErrorCondition("TestError", 4, "ErrorReason", tt.err)

			assert.Equal(t, "TestError", cond.Type)
			assert.Equal(t, metav1.ConditionFalse, cond.Status)
			assert.Equal(t, "ErrorReason", cond.Reason)
			assert.Equal(t, tt.expectedMessage, cond.Message)
		})
	}
}

func TestNewErrorConditionWithMessage(t *testing.T) {
	cond := NewErrorConditionWithMessage("CustomError", 6, "FormatError", "failed to process %d items: %s", 5, "timeout")

	assert.Equal(t, "CustomError", cond.Type)
	assert.Equal(t, metav1.ConditionFalse, cond.Status)
	assert.Equal(t, "FormatError", cond.Reason)
	assert.Equal(t, "failed to process 5 items: timeout", cond.Message)
}

func TestConditionConstants(t *testing.T) {
	// Verify constants are defined as expected
	assert.Equal(t, "Ready", ConditionTypeReady)
	assert.Equal(t, "ConfigValid", ConditionTypeConfigValid)
	assert.Equal(t, "ClusterReachable", ConditionTypeClusterReachable)
	assert.Equal(t, "Synced", ConditionTypeSynced)

	assert.Equal(t, "Success", ReasonSuccess)
	assert.Equal(t, "ValidationFailed", ReasonValidationFailed)
	assert.Equal(t, "ConfigurationError", ReasonConfigurationError)
	assert.Equal(t, "ConnectionFailed", ReasonConnectionFailed)
	assert.Equal(t, "InProgress", ReasonInProgress)
	assert.Equal(t, "Unknown", ReasonUnknown)
}
