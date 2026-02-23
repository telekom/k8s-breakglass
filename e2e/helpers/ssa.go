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

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FieldOwnerE2E is the field owner identifier for e2e test status updates.
// Using a distinct owner from the controller helps identify test-initiated changes.
const FieldOwnerE2E = "breakglass-e2e-test"

// ApplySessionStatus applies a BreakglassSession status update using SSA.
// This is the preferred method for updating session status in e2e tests as it
// mirrors production behavior and avoids field manager conflicts.
func ApplySessionStatus(ctx context.Context, c client.Client, session *breakglassv1alpha1.BreakglassSession) error {
	return ssa.ApplyBreakglassSessionStatus(ctx, c, session)
}

// ApplyDebugSessionStatus applies a DebugSession status update using SSA.
// This is the preferred method for updating debug session status in e2e tests.
func ApplyDebugSessionStatus(ctx context.Context, c client.Client, session *breakglassv1alpha1.DebugSession) error {
	return ssa.ApplyDebugSessionStatus(ctx, c, session)
}

// ApplyEscalationStatus applies a BreakglassEscalation status update using SSA.
// This is the preferred method for updating escalation status in e2e tests.
func ApplyEscalationStatus(ctx context.Context, c client.Client, escalation *breakglassv1alpha1.BreakglassEscalation) error {
	return ssa.ApplyBreakglassEscalationStatus(ctx, c, escalation)
}
