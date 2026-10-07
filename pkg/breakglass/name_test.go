package breakglass

import (
	"testing"

	"github.com/telekom/k8s-breakglass/pkg/naming"
)

func TestToRFC1123Subdomain(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"example-1.tst.region", "example-1.tst.region"},
		{"EXAMPLE-PLATFORM_EMERGENCY", "example-platform-emergency"},
		{"..leading..dots..", "leading.dots"},
		{"___underscores___", "underscores"},
		{"UPPER_and.Mix-123", "upper-and.mix-123"},
		{"...---...", "x"},
		{"", "x"},
		{"trailing-", "trailing"},
		{"-leading", "leading"},
	}

	for _, tt := range tests {
		got := naming.ToRFC1123Subdomain(tt.in)
		if got != tt.want {
			t.Fatalf("naming.ToRFC1123Subdomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
