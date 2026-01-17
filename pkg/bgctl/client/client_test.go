package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "missing server",
			opts:    []Option{},
			wantErr: true,
		},
		{
			name: "valid config",
			opts: []Option{
				WithServer("https://example.com"),
				WithToken("test-token"),
			},
			wantErr: false,
		},
		{
			name: "with custom user agent",
			opts: []Option{
				WithServer("https://example.com"),
				WithUserAgent("test-agent"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(tt.opts...)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, client)
			} else {
				require.NoError(t, err)
				require.NotNil(t, client)
			}
		})
	}
}

func TestClientDo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		require.Equal(t, "Bearer test-token", auth)

		ua := r.Header.Get("User-Agent")
		require.Equal(t, "test-agent", ua)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client, err := New(
		WithServer(server.URL),
		WithToken("test-token"),
		WithUserAgent("test-agent"),
	)
	require.NoError(t, err)

	var result map[string]string
	err = client.do(context.Background(), http.MethodGet, "/test", nil, &result)
	require.NoError(t, err)
	require.Equal(t, "ok", result["status"])
}

func TestClientDoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	err = client.do(context.Background(), http.MethodGet, "/missing", nil, nil)
	require.Error(t, err)

	httpErr, ok := err.(*HTTPError)
	require.True(t, ok)
	require.Equal(t, http.StatusNotFound, httpErr.StatusCode)
	require.Contains(t, httpErr.Message, "not found")
}

func TestHTTPError(t *testing.T) {
	err := &HTTPError{
		StatusCode: http.StatusForbidden,
		Message:    "access denied",
	}
	require.Equal(t, "request failed (403): access denied", err.Error())
}
