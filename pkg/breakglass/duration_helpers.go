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

package breakglass

import (
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	durationutils "github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
)

// ParseRetainFor parses the RetainFor duration from a session spec.
// Returns DefaultRetainForDuration if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseRetainFor(spec breakglassv1alpha1.BreakglassSessionSpec, log *zap.SugaredLogger) time.Duration {
	return durationutils.ParseRetainFor(spec, log)
}

// ParseMaxValidFor parses the MaxValidFor duration from a session spec.
// Returns DefaultValidForDuration if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseMaxValidFor(spec breakglassv1alpha1.BreakglassSessionSpec, log *zap.SugaredLogger) time.Duration {
	return durationutils.ParseDurationOrDefault(spec.MaxValidFor, DefaultValidForDuration, "MaxValidFor", log)
}

// ParseEscalationMaxValidFor parses the MaxValidFor duration from an escalation spec.
// Returns DefaultValidForDuration if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseEscalationMaxValidFor(spec breakglassv1alpha1.BreakglassEscalationSpec, log *zap.SugaredLogger) time.Duration {
	return durationutils.ParseDurationOrDefault(spec.MaxValidFor, DefaultValidForDuration, "MaxValidFor", log)
}

// ParseEscalationRetainFor parses the RetainFor duration from an escalation spec.
// Returns DefaultRetainForDuration if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseEscalationRetainFor(spec breakglassv1alpha1.BreakglassEscalationSpec, log *zap.SugaredLogger) time.Duration {
	return durationutils.ParseEscalationRetainFor(spec, log)
}

// ParseApprovalTimeout parses the ApprovalTimeout duration from an escalation spec.
// Returns the default approval timeout (1 hour) if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseApprovalTimeout(spec breakglassv1alpha1.BreakglassEscalationSpec, log *zap.SugaredLogger) time.Duration {
	const defaultApprovalTimeout = time.Hour
	return durationutils.ParseDurationOrDefault(spec.ApprovalTimeout, defaultApprovalTimeout, "ApprovalTimeout", log)
}

// ParseDurationOrDefault is a generic helper for parsing any duration string with a default.
// Useful for one-off duration parsing where the specific field helpers don't apply.
// If log is nil, no warning is logged for invalid values.
func ParseDurationOrDefault(value string, defaultValue time.Duration, fieldName string, log *zap.SugaredLogger) time.Duration {
	return durationutils.ParseDurationOrDefault(value, defaultValue, fieldName, log)
}
