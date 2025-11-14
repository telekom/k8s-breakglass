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
	lowerReason := strings.ToLower(r.Reason)
	for _, pattern := range dangerousPatterns {
		lowerPattern := strings.ToLower(pattern)
		idx := strings.Index(lowerReason, lowerPattern)
		if idx >= 0 {
			// Strip out the dangerous pattern and everything after it
			r.Reason = r.Reason[:idx]
			// Trim again and update lowercase version for next iteration
			r.Reason = strings.TrimSpace(r.Reason)
			lowerReason = strings.ToLower(r.Reason)
		}
	}

	return nil
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
