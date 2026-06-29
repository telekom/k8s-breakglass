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
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
)

const (
	MonthDuration            = time.Hour * 24 * 30
	WeekDuration             = time.Hour * 24 * 7
	DefaultValidForDuration  = time.Hour
	DefaultRetainForDuration = MonthDuration
)

// ParseRetainFor parses the RetainFor duration from a session spec.
// Returns DefaultRetainForDuration if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseRetainFor(spec breakglassv1alpha1.BreakglassSessionSpec, log *zap.SugaredLogger) time.Duration {
	return ParseDurationOrDefault(spec.RetainFor, DefaultRetainForDuration, "RetainFor", log)
}

// ParseEscalationRetainFor parses the RetainFor duration from an escalation spec.
// Returns DefaultRetainForDuration if the value is empty or invalid.
// Logs a warning if the value is present but invalid.
func ParseEscalationRetainFor(spec breakglassv1alpha1.BreakglassEscalationSpec, log *zap.SugaredLogger) time.Duration {
	return ParseDurationOrDefault(spec.RetainFor, DefaultRetainForDuration, "RetainFor", log)
}

// ParseDurationOrDefault parses a duration with the repository's extended duration syntax.
// If the value is empty, invalid, or non-positive, defaultValue is returned.
func ParseDurationOrDefault(value string, defaultValue time.Duration, fieldName string, log *zap.SugaredLogger) time.Duration {
	if value == "" {
		return defaultValue
	}

	d, err := breakglassv1alpha1.ParseDuration(value)
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
				"parsedDuration", d.String(),
				"default", defaultValue.String())
		}
		return defaultValue
	}

	return d
}
