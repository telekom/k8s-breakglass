package breakglass

import (
	"strings"
	"testing"
)

// FuzzSanitizeReason tests the SanitizeReason function with fuzzed inputs
// to ensure it handles arbitrary input without panicking and properly
// sanitizes potentially dangerous content.
func FuzzSanitizeReason(f *testing.F) {
	// Add seed corpus with various edge cases
	seeds := []string{
		"",
		"normal reason",
		"<script>alert('xss')</script>",
		"javascript:alert(1)",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<iframe src='evil.com'></iframe>",
		"data:text/html,<script>alert(1)</script>",
		"<style>body{background:red}</style>",
		"<!--hidden-->",
		"<?php echo 'hi'; ?>",
		"<% Response.Write('hi') %>",
		"eval('code')",
		"expression(alert(1))",
		"vbscript:alert(1)",
		"<form action='evil.com'><input></form>",
		"<button onclick='alert(1)'>click</button>",
		"<textarea>text</textarea>",
		"<select><option>opt</option></select>",
		"<embed src='evil.swf'>",
		"<object data='evil.swf'>",
		"<base href='evil.com'>",
		"<link href='evil.css'>",
		"<frame src='evil.com'>",
		"<frameset><frame></frameset>",
		"   leading whitespace",
		"trailing whitespace   ",
		"unicode: こんにちは",
		"emoji: 🎉🔥💀",
		"newlines\n\n\nhere",
		"tabs\t\t\there",
		"mixed <script> and normal text",
		"null\x00byte",
		"backslash\\escape",
		"quotes \"and\" 'single'",
		"ampersand & special < > chars",
		string(make([]byte, 10000)), // Large input
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, reason string) {
		req := &BreakglassSessionRequest{Reason: reason}

		// SanitizeReason should never panic
		err := req.SanitizeReason()

		// SanitizeReason currently always returns nil, but we check anyway
		if err != nil {
			// If it returns an error, that's acceptable behavior
			return
		}

		// After sanitization, the result should not contain dangerous patterns
		dangerousPatterns := []string{
			"<script", "</script",
			"<iframe", "</iframe",
			"javascript:", "data:text/html",
			"onerror=", "onload=", "onclick=", "onmouseover=",
			"eval(", "expression(", "vbscript:",
		}

		for _, pattern := range dangerousPatterns {
			if containsIgnoreCase(req.Reason, pattern) {
				t.Errorf("sanitized reason still contains dangerous pattern %q: %q", pattern, req.Reason)
			}
		}
	})
}

// FuzzValidateDuration tests the ValidateDuration function with fuzzed inputs
func FuzzValidateDuration(f *testing.F) {
	// Add seed corpus with edge cases
	f.Add(int64(0), int64(3600))      // Zero duration (use default)
	f.Add(int64(60), int64(3600))     // Minimum allowed
	f.Add(int64(59), int64(3600))     // Just below minimum
	f.Add(int64(3600), int64(3600))   // Equal to max
	f.Add(int64(3601), int64(3600))   // Just above max
	f.Add(int64(-1), int64(3600))     // Negative
	f.Add(int64(86400), int64(86400)) // 24 hours
	f.Add(int64(1), int64(1))         // Very small max
	f.Add(int64(0), int64(0))         // Both zero

	f.Fuzz(func(t *testing.T, duration int64, maxAllowed int64) {
		req := &BreakglassSessionRequest{Duration: duration}

		// ValidateDuration should never panic
		err := req.ValidateDuration(maxAllowed)

		// Validate expected behavior
		if duration == 0 {
			// Zero duration should always succeed (uses default)
			if err != nil {
				t.Errorf("ValidateDuration(%d, %d) returned unexpected error: %v", duration, maxAllowed, err)
			}
		} else if duration < 60 {
			// Below minimum should error
			if err == nil {
				t.Errorf("ValidateDuration(%d, %d) should have returned error for duration < 60", duration, maxAllowed)
			}
		} else if duration > maxAllowed {
			// Above max should error
			if err == nil {
				t.Errorf("ValidateDuration(%d, %d) should have returned error for duration > maxAllowed", duration, maxAllowed)
			}
		} else {
			// Valid duration should succeed
			if err != nil {
				t.Errorf("ValidateDuration(%d, %d) returned unexpected error: %v", duration, maxAllowed, err)
			}
		}
	})
}

// containsIgnoreCase checks if s contains substr (case-insensitive)
// Note: This uses ToLower which is safe here since we only need to check existence,
// not find the exact byte position in the original string.
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
