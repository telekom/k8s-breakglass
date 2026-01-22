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

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
)

// ParseRetainFor parses the RetainFor duration from a session spec.
// Returns DefaultRetainForDuration if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseRetainFor(spec v1alpha1.BreakglassSessionSpec, log *zap.SugaredLogger) time.Duration {
	return parseDurationWithDefault(spec.RetainFor, DefaultRetainForDuration, "RetainFor", log)
}

// ParseMaxValidFor parses the MaxValidFor duration from a session spec.
// Returns DefaultValidForDuration if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseMaxValidFor(spec v1alpha1.BreakglassSessionSpec, log *zap.SugaredLogger) time.Duration {
	return parseDurationWithDefault(spec.MaxValidFor, DefaultValidForDuration, "MaxValidFor", log)
}

// ParseEscalationMaxValidFor parses the MaxValidFor duration from an escalation spec.
// Returns DefaultValidForDuration if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseEscalationMaxValidFor(spec v1alpha1.BreakglassEscalationSpec, log *zap.SugaredLogger) time.Duration {
	return parseDurationWithDefault(spec.MaxValidFor, DefaultValidForDuration, "MaxValidFor", log)
}

// ParseEscalationRetainFor parses the RetainFor duration from an escalation spec.
// Returns DefaultRetainForDuration if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseEscalationRetainFor(spec v1alpha1.BreakglassEscalationSpec, log *zap.SugaredLogger) time.Duration {
	return parseDurationWithDefault(spec.RetainFor, DefaultRetainForDuration, "RetainFor", log)
}

// ParseApprovalTimeout parses the ApprovalTimeout duration from an escalation spec.
// Returns the default approval timeout (1 hour) if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseApprovalTimeout(spec v1alpha1.BreakglassEscalationSpec, log *zap.SugaredLogger) time.Duration {
	const defaultApprovalTimeout = time.Hour
	return parseDurationWithDefault(spec.ApprovalTimeout, defaultApprovalTimeout, "ApprovalTimeout", log)
}

// parseDurationWithDefault is the internal helper that parses a duration string.
// If the value is empty, returns defaultValue without logging.
// If the value is present but invalid, logs a warning and returns defaultValue.
// If the value is valid but <= 0, logs a warning and returns defaultValue.
// Supports extended duration units including days (e.g., "7d", "90d").
func parseDurationWithDefault(value string, defaultValue time.Duration, fieldName string, log *zap.SugaredLogger) time.Duration {
	if value == "" {
		return defaultValue
	}

	d, err := v1alpha1.ParseDuration(value)
	if err != nil {
		if log != nil {
			log.Warnw("Invalid "+fieldName+" in spec; falling back to default",
				"value", value,
				"error", err,
				"default", defaultValue.String())
		}
		return defaultValue
	}

	if d <= 0 {
		if log != nil {
			log.Warnw("Non-positive "+fieldName+" in spec; falling back to default",
				"value", value,
				"parsedDuration", d,
				"default", defaultValue.String())
		}
		return defaultValue
	}

	return d
}

// ParseDurationOrDefault is a generic helper for parsing any duration string with a default.
// Useful for one-off duration parsing where the specific field helpers don't apply.
// If log is nil, no warning is logged for invalid values.
func ParseDurationOrDefault(value string, defaultValue time.Duration, fieldName string, log *zap.SugaredLogger) time.Duration {
	return parseDurationWithDefault(value, defaultValue, fieldName, log)
}
