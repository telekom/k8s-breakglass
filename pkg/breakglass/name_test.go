package breakglass

import "testing"

func TestToRFC1123Subdomain(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"t-sec-1.tst.dtmd11", "t-sec-1.tst.dtmd11"},
		{"DTTCAAS-PLATFORM_EMERGENCY", "dttcaas-platform-emergency"},
		{"..leading..dots..", "leading.dots"},
		{"___underscores___", "underscores"},
		{"UPPER_and.Mix-123", "upper-and.mix-123"},
		{"...---...", "x"},
		{"", "x"},
		{"trailing-", "trailing"},
		{"-leading", "leading"},
	}

	for _, tt := range tests {
		got := toRFC1123Subdomain(tt.in)
		if got != tt.want {
			t.Fatalf("toRFC1123Subdomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
