package breakglass

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
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
	// Max 500 characters, sanitized on server-side to prevent injection attacks.
	Reason string `json:"reason,omitempty"`
	// Duration is the requested duration in seconds. Must not exceed the escalation's maxValidFor.
	// Optional; if not provided, uses escalation's maxValidFor.
	Duration int64 `json:"duration,omitempty"`
	// ScheduledStartTime is an optional ISO 8601 datetime for scheduling the request for a future time.
	ScheduledStartTime string `json:"scheduledStartTime,omitempty"`
}

const MaxReasonLength = 500

// allowedReasonChars is an allowlist pattern that matches characters NOT permitted in reason text.
// Only alphanumeric characters, spaces, and basic punctuation (.,;:!?'-) are permitted.
// Everything else is stripped to prevent XSS and injection attacks.
var allowedReasonChars = regexp.MustCompile(`[^a-zA-Z0-9 .,;:!?'\-]`)

// SanitizeReason sanitizes the reason field to prevent injection attacks.
// Trims whitespace, strips non-allowlisted characters, and enforces maximum length.
func (r *BreakglassSessionRequest) SanitizeReason() error {
	sanitized := SanitizeReasonText(r.Reason)
	if utf8.RuneCountInString(sanitized) > MaxReasonLength {
		return fmt.Errorf("reason must be at most %d characters", MaxReasonLength)
	}
	r.Reason = sanitized
	return nil
}

// SanitizeReasonText sanitizes a reason string to prevent injection attacks using an allowlist approach.
// Only alphanumeric characters, spaces, and basic punctuation (.,;:!?'-) are permitted.
// All other characters — including HTML tags, script injection markers, Unicode specials,
// and URL-encoded bypass attempts — are stripped. Leading/trailing whitespace is trimmed.
//
// This allowlist approach is more robust than a blacklist because it cannot be bypassed
// via encoding tricks, novel HTML tags, or patterns not yet in the deny list.
func SanitizeReasonText(reason string) string {
	// Trim leading/trailing whitespace first
	reason = strings.TrimSpace(reason)
	// Strip any character not in the allowlist
	reason = allowedReasonChars.ReplaceAllString(reason, "")
	// Re-trim in case stripping left new leading/trailing spaces
	reason = strings.TrimSpace(reason)
	return reason
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
		return fmt.Errorf("requested duration %d seconds exceeds maximum allowed %d seconds", r.Duration, maxAllowed)
	}

	return nil
}
