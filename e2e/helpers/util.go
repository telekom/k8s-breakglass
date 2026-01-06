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

package helpers

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ParseQuantity parses a resource quantity string and returns the quantity.
// Panics if the string is invalid (suitable for test code).
func ParseQuantity(s string) resource.Quantity {
	q := resource.MustParse(s)
	return q
}

// ParseDuration parses a duration string and returns the parsed duration.
// Panics if the string is invalid (suitable for test code).
func ParseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(fmt.Sprintf("invalid duration: %s", s))
	}
	return d
}

// WaitForCondition waits for a condition function to return true.
// This is an overload that takes a simple boolean function.
func WaitForConditionSimple(ctx context.Context, condition func() bool, timeout, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	timeoutCh := time.After(timeout)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeoutCh:
			return fmt.Errorf("timeout waiting for condition")
		case <-ticker.C:
			if condition() {
				return nil
			}
		}
	}
}

// StringPtr returns a pointer to a string value
func StringPtr(s string) *string {
	return &s
}

// Int32Ptr returns a pointer to an int32 value
func Int32Ptr(i int32) *int32 {
	return &i
}

// Int64Ptr returns a pointer to an int64 value
func Int64Ptr(i int64) *int64 {
	return &i
}

// BoolPtr returns a pointer to a bool value
func BoolPtr(b bool) *bool {
	return &b
}

// TimePtr returns a pointer to a metav1.Time value
func TimePtr(t metav1.Time) *metav1.Time {
	return &t
}

// NowPtr returns a pointer to the current time as metav1.Time
func NowPtr() *metav1.Time {
	now := metav1.Now()
	return &now
}

// FutureTime returns a metav1.Time in the future by the given duration
func FutureTime(d time.Duration) metav1.Time {
	return metav1.NewTime(time.Now().Add(d))
}

// PastTime returns a metav1.Time in the past by the given duration
func PastTime(d time.Duration) metav1.Time {
	return metav1.NewTime(time.Now().Add(-d))
}

// GenerateUniqueName generates a unique name for test resources
func GenerateUniqueName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, uuid.New().String()[:8])
}
