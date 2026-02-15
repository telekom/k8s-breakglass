package api

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildOIDCProxyTargetURL(t *testing.T) {
	baseWithRealm, err := url.Parse("https://example.com/realms/root")
	require.NoError(t, err)
	baseNoPath, err := url.Parse("https://example.com")
	require.NoError(t, err)

	tests := []struct {
		name           string
		base           *url.URL
		normalizedPath string
		proxyPath      string
		expectErr      error
		expectedTarget string
	}{
		{
			name:           "preserves base path and query",
			base:           baseWithRealm,
			normalizedPath: "/.well-known/openid-configuration",
			proxyPath:      "/.well-known/openid-configuration?foo=bar",
			expectedTarget: "https://example.com/realms/root/.well-known/openid-configuration?foo=bar",
		},
		{
			name:           "handles base without path",
			base:           baseNoPath,
			normalizedPath: "/protocol/openid-connect/certs",
			proxyPath:      "/protocol/openid-connect/certs",
			expectedTarget: "https://example.com/protocol/openid-connect/certs",
		},
		{
			name:           "rejects nil base",
			base:           nil,
			normalizedPath: "/.well-known/jwks.json",
			proxyPath:      "/.well-known/jwks.json",
			expectErr:      errProxyAuthorityMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := buildOIDCProxyTargetURL(tt.base, tt.normalizedPath, tt.proxyPath)
			if tt.expectErr != nil {
				require.ErrorIs(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedTarget, target.String())
		})
	}
}

func TestNormalizeProxyPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{"strips_query_and_fragment", "/token?foo=bar#frag", "/token"},
		{"preserves_encoded_segments", "/protocol/%2fopenid", "/protocol/%2fopenid"},
		{"falls_back_on_invalid", "%%%", "%%%"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expected, normalizeProxyPath(tt.input))
		})
	}
}

func TestHasEncodedTraversal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"plain_path", "/protocol/openid-connect/certs", false},
		{"single_encoding", "/protocol/%2e%2e/%2e%2e/admin", true},
		{"double_encoding", "/protocol/%252e%252e/%252e%252e/admin", true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expected, hasEncodedTraversal(tt.input))
		})
	}
}
