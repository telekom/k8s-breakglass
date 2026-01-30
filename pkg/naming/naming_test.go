package naming

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation"
)

func TestToRFC1123Subdomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string returns x", "", "x"},
		{"already valid", "valid-name", "valid-name"},
		{"preserves dots", "t-sec-1.tst.dtmd11", "t-sec-1.tst.dtmd11"},
		{"uppercase to lowercase", "UPPERCASE", "uppercase"},
		{"platform emergency", "DTTCAAS-PLATFORM_EMERGENCY", "dttcaas-platform-emergency"},
		{"leading dots removed", "..leading..dots..", "leading.dots"},
		{"underscores replaced", "___underscores___", "underscores"},
		{"mixed case with special", "UPPER_and.Mix-123", "upper-and.mix-123"},
		{"only special chars", "...---...", "x"},
		{"spaces replaced", "hello world", "hello-world"},
		{"leading hyphen removed", "-leading", "leading"},
		{"trailing hyphen removed", "trailing-", "trailing"},
		{"consecutive hyphens collapsed", "hello--world", "hello-world"},
		{"special characters replaced", "hello@world.com", "hello-world.com"},
		{"numbers preserved", "test123", "test123"},
		{"email converted", "User@Example.COM", "user-example.com"},
		{"long string truncated", strings.Repeat("a", 300), strings.Repeat("a", 253)},
		{"long string ending with hyphen truncated and trimmed", strings.Repeat("a", 252) + "-", strings.Repeat("a", 252)},
		{"multiple dots collapsed", "hello....world", "hello.world"},
		{"mixed invalid chars", "hello!@#$%world", "hello-world"},
		{"unicode converted", "héllo", "h-llo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToRFC1123Subdomain(tt.input)
			require.Equal(t, tt.expected, result)

			// Verify result passes K8s validation (unless it's our fallback value)
			if result != "x" {
				errs := validation.IsDNS1123Subdomain(result)
				require.Empty(t, errs, "result %q should be a valid DNS1123 subdomain", result)
			}
		})
	}
}

func TestToRFC1123Label(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string returns x", "", "x"},
		{"already valid", "valid-name", "valid-name"},
		{"uppercase to lowercase", "UPPERCASE", "uppercase"},
		{"special characters replaced", "hello@world", "hello-world"},
		{"long string truncated", strings.Repeat("a", 100), strings.Repeat("a", 63)},
		{"leading special after conversion", "@leading", "leading"},
		{"trailing special after conversion", "trailing@", "trailing"},
		{"email converted", "user@example.com", "user-example.com"},
		{"only special chars", "@@@###", "x"},
		{"numbers preserved", "test123", "test123"},
		{"consecutive hyphens collapsed", "hello--world", "hello-world"},
		{"dots preserved in label value", "hello.world", "hello.world"},
		{"long ending with hyphen", strings.Repeat("a", 62) + "-", strings.Repeat("a", 62)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToRFC1123Label(tt.input)
			require.Equal(t, tt.expected, result)

			// Verify result passes K8s label value validation (unless it's our fallback value)
			// Note: Label values can contain dots, unlike DNS1123 labels (which are for label keys)
			if result != "x" {
				errs := validation.IsValidLabelValue(result)
				require.Empty(t, errs, "result %q should be a valid label value", result)
			}
		})
	}
}

func TestIsAlnum(t *testing.T) {
	tests := []struct {
		input    rune
		expected bool
	}{
		{'a', true},
		{'z', true},
		{'A', false}, // uppercase not valid (input is lowercased before isAlnum is called)
		{'Z', false},
		{'0', true},
		{'9', true},
		{'-', false},
		{'_', false},
		{'@', false},
		{' ', false},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			require.Equal(t, tt.expected, isAlnum(tt.input))
		})
	}
}

func TestTrimNonAlnum(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"abc", "abc"},
		{"-abc-", "abc"},
		{"..abc..", "abc"},
		{"-.-abc-.-", "abc"},
		{"---", ""},
		{"", ""},
		{"a", "a"},
		{"-a-", "a"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			require.Equal(t, tt.expected, trimNonAlnum(tt.input))
		})
	}
}
