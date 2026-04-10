package breakglass

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClusterUserGroup_JSONMapping(t *testing.T) {
	valid := `{"cluster":"c1","user":"alice","group":"admins"}`
	var cg ClusterUserGroup
	err := json.Unmarshal([]byte(valid), &cg)
	require.NoError(t, err)
	require.Equal(t, "c1", cg.Clustername)
	require.Equal(t, "alice", cg.Username)
	require.Equal(t, "admins", cg.GroupName)

	// Missing group should produce empty GroupName
	missing := `{"cluster":"c2","user":"bob"}`
	var cg2 ClusterUserGroup
	err = json.Unmarshal([]byte(missing), &cg2)
	require.NoError(t, err)
	require.Equal(t, "", cg2.GroupName)

	// Extra fields should be ignored
	extra := `{"cluster":"c3","user":"eve","group":"ops","extra":"x"}`
	var cg3 ClusterUserGroup
	err = json.Unmarshal([]byte(extra), &cg3)
	require.NoError(t, err)
	require.Equal(t, "ops", cg3.GroupName)
}

func TestBreakglassSessionRequest_JSONMapping(t *testing.T) {
	valid := `{"cluster":"c1","user":"alice","group":"admins","reason":"need access"}`
	var req BreakglassSessionRequest
	err := json.Unmarshal([]byte(valid), &req)
	require.NoError(t, err)
	require.Equal(t, "c1", req.Clustername)
	require.Equal(t, "alice", req.Username)
	require.Equal(t, "admins", req.GroupName)
	require.Equal(t, "need access", req.Reason)

	// Empty JSON should succeed but fields empty
	var empty BreakglassSessionRequest
	err = json.Unmarshal([]byte(`{}`), &empty)
	require.NoError(t, err)
	require.Equal(t, "", empty.Clustername)
	require.Equal(t, "", empty.Username)
	require.Equal(t, "", empty.GroupName)
}

// TestBreakglassSessionRequest_SanitizeReason tests the reason field sanitization.
// Covers: trimming whitespace, enforcing character limit, preventing injection attacks.
func TestBreakglassSessionRequest_SanitizeReason(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid short reason",
			input:   "Need access for debugging",
			want:    "Need access for debugging",
			wantErr: false,
		},
		{
			name:    "reason with leading/trailing whitespace",
			input:   "  Need access for debugging  \n\t",
			want:    "Need access for debugging",
			wantErr: false,
		},
		{
			name:    "empty reason after trimming",
			input:   "   \n\t  ",
			want:    "",
			wantErr: false,
		},
		{
			name:    "reason at max length (500 chars) - accepted",
			input:   strings.Repeat("a", 500),
			want:    strings.Repeat("a", 500),
			wantErr: false,
		},
		{
			name:    "reason exceeding max length (501 chars) - rejected",
			input:   strings.Repeat("a", 501),
			want:    "",
			wantErr: true,
			errMsg:  "at most",
		},
		{
			name:    "XSS script tag stripped by allowlist",
			input:   "<script>alert('xss')</script>",
			want:    "scriptalert'xss'script",
			wantErr: false,
		},
		{
			name:    "SQL injection attempt - safe chars pass through",
			input:   "'; DROP TABLE sessions; --",
			want:    "'; DROP TABLE sessions; --",
			wantErr: false,
		},
		{
			name:    "reason with basic punctuation preserved",
			input:   "Debugging prod issue - server down. Please help!",
			want:    "Debugging prod issue - server down. Please help!",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &BreakglassSessionRequest{Reason: tt.input}
			err := req.SanitizeReason()

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, req.Reason)
			}
		})
	}
}

// TestBreakglassSessionRequest_ValidateDuration tests duration validation.
// Covers: minimum duration (60s), maximum duration boundary, zero/unspecified duration.
func TestBreakglassSessionRequest_ValidateDuration(t *testing.T) {
	tests := []struct {
		name       string
		duration   int64
		maxAllowed int64
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "valid duration at minimum (60 seconds)",
			duration:   60,
			maxAllowed: 3600,
			wantErr:    false,
		},
		{
			name:       "valid duration in middle",
			duration:   1800,
			maxAllowed: 3600,
			wantErr:    false,
		},
		{
			name:       "valid duration at maximum",
			duration:   3600,
			maxAllowed: 3600,
			wantErr:    false,
		},
		{
			name:       "zero duration (unspecified, should use default)",
			duration:   0,
			maxAllowed: 3600,
			wantErr:    false,
		},
		{
			name:       "duration below minimum (59 seconds)",
			duration:   59,
			maxAllowed: 3600,
			wantErr:    true,
			errMsg:     "at least 60 seconds",
		},
		{
			name:       "duration exceeds maximum",
			duration:   3601,
			maxAllowed: 3600,
			wantErr:    true,
			errMsg:     "exceeds maximum allowed",
		},
		{
			name:       "negative duration",
			duration:   -100,
			maxAllowed: 3600,
			wantErr:    true,
			errMsg:     "at least 60 seconds",
		},
		{
			name:       "large valid duration",
			duration:   86400, // 24 hours
			maxAllowed: 86400,
			wantErr:    false,
		},
		{
			name:       "large duration exceeds large max",
			duration:   86401,
			maxAllowed: 86400,
			wantErr:    true,
			errMsg:     "exceeds maximum allowed",
		},
		{
			name:       "very small maxAllowed (1 second)",
			duration:   60,
			maxAllowed: 1,
			wantErr:    true,
			errMsg:     "exceeds maximum allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &BreakglassSessionRequest{Duration: tt.duration}
			err := req.ValidateDuration(tt.maxAllowed)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestBreakglassSessionRequest_CombinedValidation tests sanitizing and validating together.
// Ensures that reason sanitization and duration validation can both be called successfully.
func TestBreakglassSessionRequest_CombinedValidation(t *testing.T) {
	tests := []struct {
		name            string
		reason          string
		duration        int64
		maxAllowed      int64
		wantReasonErr   bool
		wantDurationErr bool
	}{
		{
			name:            "both valid",
			reason:          "Testing system access",
			duration:        1800,
			maxAllowed:      3600,
			wantReasonErr:   false,
			wantDurationErr: false,
		},
		{
			name:            "long reason (rejected), valid duration",
			reason:          strings.Repeat("a", 501),
			duration:        1800,
			maxAllowed:      3600,
			wantReasonErr:   true,
			wantDurationErr: false,
		},
		{
			name:            "reason with XSS chars stripped, valid duration",
			reason:          "Normal text <script>alert('xss')</script> more text",
			duration:        1800,
			maxAllowed:      3600,
			wantReasonErr:   false,
			wantDurationErr: false,
		},
		{
			name:            "valid reason, invalid duration",
			reason:          "Testing system access",
			duration:        3700,
			maxAllowed:      3600,
			wantReasonErr:   false,
			wantDurationErr: true,
		},
		{
			name:            "invalid duration, long reason",
			reason:          strings.Repeat("a", 501),
			duration:        -100,
			maxAllowed:      3600,
			wantReasonErr:   true,
			wantDurationErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &BreakglassSessionRequest{
				Reason:   tt.reason,
				Duration: tt.duration,
			}

			reasonErr := req.SanitizeReason()
			durationErr := req.ValidateDuration(tt.maxAllowed)

			if tt.wantReasonErr {
				require.Error(t, reasonErr)
			} else {
				require.NoError(t, reasonErr)
			}

			if tt.wantDurationErr {
				require.Error(t, durationErr)
			} else {
				require.NoError(t, durationErr)
			}
		})
	}
}

// TestSanitizeReasonText tests the standalone SanitizeReasonText function.
// Verifies allowlist behavior: only alphanumeric, spaces, and .,;!?'- are permitted (colon excluded).
func TestSanitizeReasonText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "simple text",
			input:    "Need elevated access for debugging",
			expected: "Need elevated access for debugging",
		},
		{
			name:     "text with leading and trailing whitespace",
			input:    "  Need access  ",
			expected: "Need access",
		},
		{
			name:     "basic punctuation preserved",
			input:    "Prod is down - needs fix. Please help!",
			expected: "Prod is down - needs fix. Please help!",
		},
		{
			name:     "XSS: script tag stripped",
			input:    "<script>alert('xss')</script>",
			expected: "scriptalert'xss'script",
		},
		{
			name:     "XSS: uppercase script tag stripped",
			input:    "<SCRIPT>alert('xss')</SCRIPT>",
			expected: "SCRIPTalert'xss'SCRIPT",
		},
		{
			name:     "XSS: mixed case script tag stripped",
			input:    "Normal text<ScRiPt>alert('xss')</ScRiPt>",
			expected: "Normal textScRiPtalert'xss'ScRiPt",
		},
		{
			name:     "XSS: javascript protocol stripped",
			input:    "Click here javascript alert(1)",
			expected: "Click here javascript alert1",
		},
		{
			name:     "XSS: javascript colon stripped",
			input:    "javascript:alert(1)",
			expected: "javascriptalert1",
		},
		{
			name:     "XSS: onerror event handler stripped",
			input:    "Image onerror=alert(1)",
			expected: "Image onerroralert1",
		},
		{
			name:     "XSS: onclick stripped",
			input:    "Button onclick=doEvil()",
			expected: "Button onclickdoEvil",
		},
		{
			name:     "XSS: img tag stripped",
			input:    `<img src="x" onerror="alert(1)">`,
			expected: "img srcx onerroralert1",
		},
		{
			name:     "XSS: URL-encoded payload - percent signs stripped",
			input:    "%3Cscript%3Ealert(1)%3C/script%3E",
			expected: "3Cscript3Ealert13Cscript3E",
		},
		{
			name:     "Unicode special chars stripped",
			input:    "Hello \u2603 World",
			expected: "Hello  World",
		},
		{
			name:     "emoji stripped",
			input:    "Debugging \U0001F525 production",
			expected: "Debugging  production",
		},
		{
			name:     "null byte stripped",
			input:    "null\x00byte",
			expected: "nullbyte",
		},
		{
			name:     "newlines and tabs stripped",
			input:    "Line1\nLine2\r\nLine3\tTab",
			expected: "Line1Line2Line3Tab",
		},
		{
			name:     "ampersand and angle brackets stripped",
			input:    "ampersand & special < > chars",
			expected: "ampersand  special   chars",
		},
		{
			name:     "hyphen preserved",
			input:    "long-running incident",
			expected: "long-running incident",
		},
		{
			name:     "apostrophe preserved",
			input:    "customer's data",
			expected: "customer's data",
		},
		{
			name:     "only whitespace",
			input:    "   \n\t  ",
			expected: "",
		},
		{
			name:     "backslash stripped",
			input:    "path\\to\\file",
			expected: "pathtofile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeReasonText(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}
