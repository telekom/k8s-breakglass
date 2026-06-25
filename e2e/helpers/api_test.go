package helpers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIClientRefreshesTokenOnceOnUnauthorized(t *testing.T) {
	var authHeaders []string
	var correlationIDs []string

	client := NewAPIClientWithAuth("stale-token").
		WithTokenRefresh(func(context.Context) string {
			return "fresh-token"
		})
	client.BaseURL = "http://breakglass.test"
	client.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		correlationIDs = append(correlationIDs, r.Header.Get(CorrelationIDHeader))
		if len(authHeaders) == 1 {
			return testResponse(http.StatusUnauthorized, `{"error":"stale token"}`), nil
		}
		_, _ = io.Copy(io.Discard, r.Body)
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	})}

	refreshCalls := 0
	client.RefreshToken = func(context.Context) string {
		refreshCalls++
		return "fresh-token"
	}

	resp, err := client.doRequestWithCID(context.Background(), http.MethodPost, "/sessions", map[string]string{"reason": "test"}, "cid-123")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, refreshCalls)
	assert.Equal(t, []string{"Bearer stale-token", "Bearer fresh-token"}, authHeaders)
	assert.Equal(t, []string{"cid-123", "cid-123"}, correlationIDs)
}

func TestAPIClientDoesNotRefreshIntentionalUnauthorizedRequests(t *testing.T) {
	client := NewAPIClientWithAuth("invalid-token")
	client.BaseURL = "http://breakglass.test"
	client.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusUnauthorized, `{"error":"invalid token"}`), nil
	})}

	resp, err := client.doRequestWithCID(context.Background(), http.MethodGet, "/sessions", nil, "cid-123")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "invalid-token", client.AuthToken)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func testResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
