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

// Package utils provides shared utilities for the breakglass controller.
package utils

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DefaultStatusUpdateMinInterval is the default minimum interval between status updates.
// If a status was updated recently by another controller replica, we skip the update to avoid conflicts.
const DefaultStatusUpdateMinInterval = 30 * time.Second

// StatusCoordinator provides utilities for coordinating status updates across multiple
// controller replicas without leader election. It prevents redundant status updates by
// checking if the status was recently updated to the same state.
//
// Key principles:
// 1. Always perform actual work (cache refreshes, config reloads, etc.)
// 2. Only skip the status UPDATE if another controller recently set the same state
// 3. Emit events when skipping to maintain visibility
type StatusCoordinator struct {
	// MinInterval is the minimum time between status updates.
	// Updates within this interval are skipped if the state already matches.
	MinInterval time.Duration
}

// NewStatusCoordinator creates a new StatusCoordinator with the default interval.
func NewStatusCoordinator() *StatusCoordinator {
	return &StatusCoordinator{
		MinInterval: DefaultStatusUpdateMinInterval,
	}
}

// NewStatusCoordinatorWithInterval creates a new StatusCoordinator with a custom interval.
func NewStatusCoordinatorWithInterval(interval time.Duration) *StatusCoordinator {
	return &StatusCoordinator{
		MinInterval: interval,
	}
}

// ShouldSkipStatusUpdate determines if a status update should be skipped because
// another controller recently set the same condition state.
//
// Parameters:
//   - conditions: The current conditions from the resource status
//   - conditionType: The type of condition to check (e.g., "Ready")
//   - desiredStatus: The status we want to set (e.g., metav1.ConditionTrue)
//   - desiredReason: Optional - if set, also checks that the reason matches
//
// Returns true if:
// 1. The condition exists with the desired status (and reason if specified)
// 2. The condition's LastTransitionTime is within MinInterval
func (sc *StatusCoordinator) ShouldSkipStatusUpdate(
	conditions []metav1.Condition,
	conditionType string,
	desiredStatus metav1.ConditionStatus,
	desiredReason string,
) bool {
	for _, c := range conditions {
		if c.Type != conditionType {
			continue
		}

		// Check if status matches
		if c.Status != desiredStatus {
			return false
		}

		// Check if reason matches (if specified)
		if desiredReason != "" && c.Reason != desiredReason {
			return false
		}

		// Check if the condition was recently updated
		return time.Since(c.LastTransitionTime.Time) < sc.MinInterval
	}

	// Condition doesn't exist, need to create it
	return false
}

// ShouldSkipStatusUpdateByTime is a simpler check using just a timestamp.
// Use this for resources that have a dedicated LastCheck/LastHealthCheck field.
func (sc *StatusCoordinator) ShouldSkipStatusUpdateByTime(lastCheck *metav1.Time) bool {
	if lastCheck == nil {
		return false
	}
	return time.Since(lastCheck.Time) < sc.MinInterval
}

// ShouldSkipStatusUpdateByGeneration checks if status should be skipped based on
// ObservedGeneration matching the current generation AND recent update time.
func (sc *StatusCoordinator) ShouldSkipStatusUpdateByGeneration(
	conditions []metav1.Condition,
	conditionType string,
	desiredStatus metav1.ConditionStatus,
	currentGeneration int64,
	observedGeneration int64,
) bool {
	// If generation changed, always update
	if observedGeneration != currentGeneration {
		return false
	}

	return sc.ShouldSkipStatusUpdate(conditions, conditionType, desiredStatus, "")
}

// SkipReason represents the reason for skipping a status update.
type SkipReason string

const (
	// SkipReasonRecentUpdate indicates the status was recently updated by another controller.
	SkipReasonRecentUpdate SkipReason = "RecentStatusUpdate"
	// SkipReasonSameState indicates the status is already in the desired state.
	SkipReasonSameState SkipReason = "StatusUnchanged"
)

// SkipInfo contains information about a skipped status update.
type SkipInfo struct {
	Skipped         bool
	Reason          SkipReason
	LastUpdateAge   time.Duration
	ExistingStatus  metav1.ConditionStatus
	ExistingReason  string
	ExistingMessage string
}

// ShouldSkipStatusUpdateDetailed returns detailed information about why the update
// should or should not be skipped. Use this for emitting events about skipped updates.
func (sc *StatusCoordinator) ShouldSkipStatusUpdateDetailed(
	conditions []metav1.Condition,
	conditionType string,
	desiredStatus metav1.ConditionStatus,
	desiredReason string,
) SkipInfo {
	for _, c := range conditions {
		if c.Type != conditionType {
			continue
		}

		age := time.Since(c.LastTransitionTime.Time)
		info := SkipInfo{
			LastUpdateAge:   age,
			ExistingStatus:  c.Status,
			ExistingReason:  c.Reason,
			ExistingMessage: c.Message,
		}

		// Check if status matches
		if c.Status != desiredStatus {
			info.Skipped = false
			return info
		}

		// Check if reason matches (if specified)
		if desiredReason != "" && c.Reason != desiredReason {
			info.Skipped = false
			return info
		}

		// Check if recent
		if age < sc.MinInterval {
			info.Skipped = true
			info.Reason = SkipReasonRecentUpdate
			return info
		}

		info.Skipped = false
		return info
	}

	// Condition doesn't exist
	return SkipInfo{Skipped: false}
}
