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
)

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

// GenerateUniqueName generates a unique name for test resources
func GenerateUniqueName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, uuid.New().String()[:8])
}

// WaitForNextUnixSecond blocks until time.Now().Unix() increments, ensuring
// that consecutive session names (which embed Unix seconds) are unique.
// It polls in short intervals so it only sleeps as long as actually needed.
func WaitForNextUnixSecond() {
	target := time.Now().Unix() + 1
	for time.Now().Unix() < target {
		time.Sleep(50 * time.Millisecond)
	}
}
