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
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Common condition types used across CRD statuses.
const (
	// ConditionTypeReady indicates the resource is fully operational.
	ConditionTypeReady = "Ready"

	// ConditionTypeConfigValid indicates the resource configuration is valid.
	ConditionTypeConfigValid = "ConfigValid"

	// ConditionTypeClusterReachable indicates the target cluster is reachable.
	ConditionTypeClusterReachable = "ClusterReachable"

	// ConditionTypeSynced indicates the resource has been synced.
	ConditionTypeSynced = "Synced"
)

// Common condition reasons.
const (
	// ReasonSuccess indicates successful operation.
	ReasonSuccess = "Success"

	// ReasonValidationFailed indicates validation errors.
	ReasonValidationFailed = "ValidationFailed"

	// ReasonConfigurationError indicates a configuration problem.
	ReasonConfigurationError = "ConfigurationError"

	// ReasonConnectionFailed indicates a connection problem.
	ReasonConnectionFailed = "ConnectionFailed"

	// ReasonInProgress indicates an operation is in progress.
	ReasonInProgress = "InProgress"

	// ReasonUnknown indicates an unknown state.
	ReasonUnknown = "Unknown"
)

// NewCondition creates a new metav1.Condition with all fields populated.
// This helper ensures consistent condition creation across all CRDs.
func NewCondition(
	condType string,
	status metav1.ConditionStatus,
	generation int64,
	reason string,
	message string,
) metav1.Condition {
	return metav1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
}

// NewReadyCondition creates a Ready condition.
// Pass ready=true for success, ready=false for failure.
func NewReadyCondition(generation int64, ready bool, reason, message string) metav1.Condition {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	return NewCondition(ConditionTypeReady, status, generation, reason, message)
}

// NewReadyConditionTrue creates a Ready=True condition.
func NewReadyConditionTrue(generation int64, message string) metav1.Condition {
	return NewReadyCondition(generation, true, ReasonSuccess, message)
}

// NewReadyConditionFalse creates a Ready=False condition with the given reason.
func NewReadyConditionFalse(generation int64, reason, message string) metav1.Condition {
	return NewReadyCondition(generation, false, reason, message)
}

// NewConfigValidCondition creates a ConfigValid condition.
func NewConfigValidCondition(generation int64, valid bool, reason, message string) metav1.Condition {
	status := metav1.ConditionFalse
	if valid {
		status = metav1.ConditionTrue
	}
	return NewCondition(ConditionTypeConfigValid, status, generation, reason, message)
}

// NewClusterReachableCondition creates a ClusterReachable condition.
func NewClusterReachableCondition(generation int64, reachable bool, reason, message string) metav1.Condition {
	status := metav1.ConditionFalse
	if reachable {
		status = metav1.ConditionTrue
	}
	return NewCondition(ConditionTypeClusterReachable, status, generation, reason, message)
}

// NewErrorCondition creates a condition indicating an error state.
// This is a convenience wrapper for common error reporting patterns.
func NewErrorCondition(condType string, generation int64, reason string, err error) metav1.Condition {
	message := "Unknown error"
	if err != nil {
		message = err.Error()
	}
	return NewCondition(condType, metav1.ConditionFalse, generation, reason, message)
}

// NewErrorConditionWithMessage creates a condition with a formatted error message.
func NewErrorConditionWithMessage(condType string, generation int64, reason string, format string, args ...interface{}) metav1.Condition {
	return NewCondition(condType, metav1.ConditionFalse, generation, reason, fmt.Sprintf(format, args...))
}
