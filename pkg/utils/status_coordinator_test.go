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

package utils

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewStatusCoordinator(t *testing.T) {
	sc := NewStatusCoordinator()
	if sc.MinInterval != DefaultStatusUpdateMinInterval {
		t.Errorf("expected default interval %v, got %v", DefaultStatusUpdateMinInterval, sc.MinInterval)
	}
}

func TestNewStatusCoordinatorWithInterval(t *testing.T) {
	interval := 1 * time.Minute
	sc := NewStatusCoordinatorWithInterval(interval)
	if sc.MinInterval != interval {
		t.Errorf("expected interval %v, got %v", interval, sc.MinInterval)
	}
}

func TestShouldSkipStatusUpdate(t *testing.T) {
	now := metav1.Now()
	recentTime := metav1.NewTime(time.Now().Add(-10 * time.Second)) // 10 seconds ago
	oldTime := metav1.NewTime(time.Now().Add(-2 * time.Minute))     // 2 minutes ago

	tests := []struct {
		name          string
		conditions    []metav1.Condition
		conditionType string
		desiredStatus metav1.ConditionStatus
		desiredReason string
		minInterval   time.Duration
		expectSkip    bool
	}{
		{
			name:          "no conditions - should not skip",
			conditions:    []metav1.Condition{},
			conditionType: "Ready",
			desiredStatus: metav1.ConditionTrue,
			desiredReason: "",
			minInterval:   30 * time.Second,
			expectSkip:    false,
		},
		{
			name: "condition exists, same status, recent - should skip",
			conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Configured",
					LastTransitionTime: recentTime,
				},
			},
			conditionType: "Ready",
			desiredStatus: metav1.ConditionTrue,
			desiredReason: "",
			minInterval:   30 * time.Second,
			expectSkip:    true,
		},
		{
			name: "condition exists, same status, old - should not skip",
			conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Configured",
					LastTransitionTime: oldTime,
				},
			},
			conditionType: "Ready",
			desiredStatus: metav1.ConditionTrue,
			desiredReason: "",
			minInterval:   30 * time.Second,
			expectSkip:    false,
		},
		{
			name: "condition exists, different status - should not skip",
			conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionFalse,
					Reason:             "Failed",
					LastTransitionTime: recentTime,
				},
			},
			conditionType: "Ready",
			desiredStatus: metav1.ConditionTrue,
			desiredReason: "",
			minInterval:   30 * time.Second,
			expectSkip:    false,
		},
		{
			name: "condition exists, same status, different reason - should not skip when reason specified",
			conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "OldReason",
					LastTransitionTime: recentTime,
				},
			},
			conditionType: "Ready",
			desiredStatus: metav1.ConditionTrue,
			desiredReason: "NewReason",
			minInterval:   30 * time.Second,
			expectSkip:    false,
		},
		{
			name: "condition exists, same status and reason, recent - should skip",
			conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Configured",
					LastTransitionTime: recentTime,
				},
			},
			conditionType: "Ready",
			desiredStatus: metav1.ConditionTrue,
			desiredReason: "Configured",
			minInterval:   30 * time.Second,
			expectSkip:    true,
		},
		{
			name: "wrong condition type - should not skip",
			conditions: []metav1.Condition{
				{
					Type:               "Healthy",
					Status:             metav1.ConditionTrue,
					Reason:             "Configured",
					LastTransitionTime: now,
				},
			},
			conditionType: "Ready",
			desiredStatus: metav1.ConditionTrue,
			desiredReason: "",
			minInterval:   30 * time.Second,
			expectSkip:    false,
		},
		{
			name: "multiple conditions, target matches - should skip",
			conditions: []metav1.Condition{
				{
					Type:               "Healthy",
					Status:             metav1.ConditionFalse,
					Reason:             "Unhealthy",
					LastTransitionTime: oldTime,
				},
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Configured",
					LastTransitionTime: recentTime,
				},
			},
			conditionType: "Ready",
			desiredStatus: metav1.ConditionTrue,
			desiredReason: "",
			minInterval:   30 * time.Second,
			expectSkip:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := NewStatusCoordinatorWithInterval(tt.minInterval)
			result := sc.ShouldSkipStatusUpdate(tt.conditions, tt.conditionType, tt.desiredStatus, tt.desiredReason)
			if result != tt.expectSkip {
				t.Errorf("expected skip=%v, got %v", tt.expectSkip, result)
			}
		})
	}
}

func TestShouldSkipStatusUpdateByTime(t *testing.T) {
	tests := []struct {
		name        string
		lastCheck   *metav1.Time
		minInterval time.Duration
		expectSkip  bool
	}{
		{
			name:        "nil lastCheck - should not skip",
			lastCheck:   nil,
			minInterval: 30 * time.Second,
			expectSkip:  false,
		},
		{
			name:        "recent lastCheck - should skip",
			lastCheck:   ptr(metav1.NewTime(time.Now().Add(-10 * time.Second))),
			minInterval: 30 * time.Second,
			expectSkip:  true,
		},
		{
			name:        "old lastCheck - should not skip",
			lastCheck:   ptr(metav1.NewTime(time.Now().Add(-2 * time.Minute))),
			minInterval: 30 * time.Second,
			expectSkip:  false,
		},
		{
			name:        "exactly at boundary - should not skip",
			lastCheck:   ptr(metav1.NewTime(time.Now().Add(-30 * time.Second))),
			minInterval: 30 * time.Second,
			expectSkip:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := NewStatusCoordinatorWithInterval(tt.minInterval)
			result := sc.ShouldSkipStatusUpdateByTime(tt.lastCheck)
			if result != tt.expectSkip {
				t.Errorf("expected skip=%v, got %v", tt.expectSkip, result)
			}
		})
	}
}

func TestShouldSkipStatusUpdateByGeneration(t *testing.T) {
	recentTime := metav1.NewTime(time.Now().Add(-10 * time.Second))

	tests := []struct {
		name               string
		conditions         []metav1.Condition
		conditionType      string
		desiredStatus      metav1.ConditionStatus
		currentGeneration  int64
		observedGeneration int64
		expectSkip         bool
	}{
		{
			name: "generation mismatch - should not skip",
			conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue, LastTransitionTime: recentTime},
			},
			conditionType:      "Ready",
			desiredStatus:      metav1.ConditionTrue,
			currentGeneration:  2,
			observedGeneration: 1,
			expectSkip:         false,
		},
		{
			name: "generation matches, condition recent - should skip",
			conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue, LastTransitionTime: recentTime},
			},
			conditionType:      "Ready",
			desiredStatus:      metav1.ConditionTrue,
			currentGeneration:  1,
			observedGeneration: 1,
			expectSkip:         true,
		},
		{
			name:               "generation matches, no conditions - should not skip",
			conditions:         []metav1.Condition{},
			conditionType:      "Ready",
			desiredStatus:      metav1.ConditionTrue,
			currentGeneration:  1,
			observedGeneration: 1,
			expectSkip:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := NewStatusCoordinator()
			result := sc.ShouldSkipStatusUpdateByGeneration(
				tt.conditions,
				tt.conditionType,
				tt.desiredStatus,
				tt.currentGeneration,
				tt.observedGeneration,
			)
			if result != tt.expectSkip {
				t.Errorf("expected skip=%v, got %v", tt.expectSkip, result)
			}
		})
	}
}

func TestShouldSkipStatusUpdateDetailed(t *testing.T) {
	recentTime := metav1.NewTime(time.Now().Add(-10 * time.Second))

	tests := []struct {
		name           string
		conditions     []metav1.Condition
		conditionType  string
		desiredStatus  metav1.ConditionStatus
		desiredReason  string
		expectSkip     bool
		expectReason   SkipReason
		expectHasAge   bool
		expectExisting bool
	}{
		{
			name:           "no conditions - should not skip",
			conditions:     []metav1.Condition{},
			conditionType:  "Ready",
			desiredStatus:  metav1.ConditionTrue,
			desiredReason:  "",
			expectSkip:     false,
			expectReason:   "",
			expectHasAge:   false,
			expectExisting: false,
		},
		{
			name: "recent update - should skip with RecentStatusUpdate",
			conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Configured", Message: "All good", LastTransitionTime: recentTime},
			},
			conditionType:  "Ready",
			desiredStatus:  metav1.ConditionTrue,
			desiredReason:  "",
			expectSkip:     true,
			expectReason:   SkipReasonRecentUpdate,
			expectHasAge:   true,
			expectExisting: true,
		},
		{
			name: "different status - should not skip with existing info",
			conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionFalse, Reason: "Failed", Message: "Error", LastTransitionTime: recentTime},
			},
			conditionType:  "Ready",
			desiredStatus:  metav1.ConditionTrue,
			desiredReason:  "",
			expectSkip:     false,
			expectReason:   "",
			expectHasAge:   true,
			expectExisting: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := NewStatusCoordinator()
			info := sc.ShouldSkipStatusUpdateDetailed(tt.conditions, tt.conditionType, tt.desiredStatus, tt.desiredReason)

			if info.Skipped != tt.expectSkip {
				t.Errorf("expected Skipped=%v, got %v", tt.expectSkip, info.Skipped)
			}
			if info.Skipped && info.Reason != tt.expectReason {
				t.Errorf("expected Reason=%v, got %v", tt.expectReason, info.Reason)
			}
			if tt.expectHasAge && info.LastUpdateAge == 0 {
				t.Error("expected LastUpdateAge to be set")
			}
			if tt.expectExisting && info.ExistingStatus == "" {
				t.Error("expected ExistingStatus to be set")
			}
		})
	}
}

// ptr is a helper to get a pointer to a value
func ptr[T any](v T) *T {
	return &v
}
