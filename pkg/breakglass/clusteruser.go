package breakglass

import (
	"strings"

	"github.com/pkg/errors"
)

type ClusterUserGroup struct {
	Clustername string `json:"cluster,omitempty"`
	Username    string `json:"user,omitempty"`
	// NOTE: previously json tag was `clustergroup` which did not match request body key `groupname`
	// causing empty GroupName and 422 on session requests. Aligning tag with request payload.
	// API now expects key `group` instead of `groupname`.
	GroupName string `json:"group,omitempty"`
}

// BreakglassSessionRequest is the expected payload when requesting a session via the API.
type BreakglassSessionRequest struct {
	Clustername string `json:"cluster,omitempty"`
	Username    string `json:"user,omitempty"`
	GroupName   string `json:"group,omitempty"`
	// Reason is an optional free-text field supplied by the requester. Its requirement and description
	// are driven by the escalation's RequestReason configuration.
	// Max 1024 characters, sanitized on server-side to prevent injection attacks.
	Reason string `json:"reason,omitempty"`
	// Duration is the requested duration in seconds. Must not exceed the escalation's maxValidFor.
	// Optional; if not provided, uses escalation's maxValidFor.
	Duration int64 `json:"duration,omitempty"`
	// ScheduledStartTime is an optional ISO 8601 datetime for scheduling the request for a future time.
	ScheduledStartTime string `json:"scheduledStartTime,omitempty"`
}

// SanitizeReason sanitizes the reason field to prevent injection attacks.
// Trims whitespace and removes dangerous HTML/JS/TS patterns while preserving safe content.
// Does not enforce a hard length limit - frontend handles length validation.
func (r *BreakglassSessionRequest) SanitizeReason() error {
	// Trim whitespace
	r.Reason = strings.TrimSpace(r.Reason)

	// Remove HTML/JS/TS potentially dangerous characters and patterns
	// This prevents injection of script tags, event handlers, and other malicious content
	dangerousPatterns := []string{
		"<script", "</script",
		"<iframe", "</iframe",
		"javascript:", "data:text/html",
		"onerror=", "onload=", "onclick=", "onmouseover=",
		"<svg", "</svg",
		"<object", "</object",
		"<embed", "</embed",
		"<link", "</link",
		"<style", "</style",
		"<img", "</img",
		"<frame", "</frame",
		"<frameset", "</frameset",
		"<base",
		"<form", "</form",
		"<input", "</input",
		"<button", "</button",
		"<textarea", "</textarea",
		"<select", "</select",
		"<option", "</option",
		"<label",
		"<legend",
		"<fieldset",
		"eval(", "expression(", "vbscript:",
		"<!--", "-->", // HTML comments can hide malicious content
		"<?php", "<?=", "?>", // PHP injection
		"<%", "%>", // ASP injection
	}

	// Check each pattern in a case-insensitive manner
	// We iterate multiple times until no more patterns are found to handle nested cases
	for {
		foundPattern := false
		for _, pattern := range dangerousPatterns {
			// Find pattern case-insensitively by searching in the original string
			// We need to find the byte position in the original string, not the lowercased one
			idx := indexCaseInsensitive(r.Reason, pattern)
			if idx >= 0 {
				// Strip out the dangerous pattern and everything after it
				r.Reason = r.Reason[:idx]
				r.Reason = strings.TrimSpace(r.Reason)
				foundPattern = true
				break // Restart the loop with the modified string
			}
		}
		if !foundPattern {
			break
		}
	}

	return nil
}

// indexCaseInsensitive finds the byte index of pattern in s using case-insensitive matching.
// Returns -1 if not found. This returns the index in the ORIGINAL string s, which is required
// for safe slicing.
//
// IMPORTANT: We cannot use strings.Index(strings.ToLower(s), strings.ToLower(pattern)) because
// ToLower can change byte lengths for certain Unicode characters (e.g., some multi-byte chars).
// Using an index from the lowercased string to slice the original would cause panics or
// incorrect results. This was discovered via fuzz testing.
func indexCaseInsensitive(s, pattern string) int {
	if len(pattern) == 0 {
		return 0
	}
	if len(s) < len(pattern) {
		return -1
	}

	// Iterate through each possible starting position in the original string.
	// strings.EqualFold handles Unicode case folding correctly.
	for i := 0; i <= len(s)-len(pattern); i++ {
		if strings.EqualFold(s[i:i+len(pattern)], pattern) {
			return i
		}
	}
	return -1
}

// ValidateDuration validates that the requested duration is within acceptable bounds.
// maxAllowed is the maximum allowed duration in seconds (from the escalation config).
func (r *BreakglassSessionRequest) ValidateDuration(maxAllowed int64) error {
	// If duration is 0 or not specified, it will use the default (maxAllowed) from escalation
	if r.Duration == 0 {
		return nil // Will use default
	}

	// Duration must be positive
	if r.Duration < 60 {
		return errors.New("duration must be at least 60 seconds (1 minute)")
	}

	// Duration must not exceed maximum allowed
	if r.Duration > maxAllowed {
		return errors.Errorf("requested duration %d seconds exceeds maximum allowed %d seconds", r.Duration, maxAllowed)
	}

	return nil
}
