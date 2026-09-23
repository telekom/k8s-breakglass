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

func TestTerminateDebugSessionRetriesOnlyBoundedOptimisticConflicts(t *testing.T) {
	for _, test := range []struct {
		name      string
		first     int
		body      string
		next      int
		calls     int
		cancel    bool
		wantError bool
	}{
		{name: "conflict then success", first: 409, body: `{"code":"CONFLICT"}`, next: 200, calls: 2},
		{name: "conflict then denied", first: 409, body: `{"code":"CONFLICT"}`, next: 403, calls: 2, wantError: true},
		{name: "bounded conflicts", first: 409, body: `{"code":"CONFLICT"}`, next: 409, calls: 4, wantError: true},
		{name: "unrelated conflict", first: 409, body: `{"code":"OTHER"}`, calls: 1, wantError: true},
		{name: "malformed conflict", first: 409, body: `{`, calls: 1, wantError: true},
		{name: "forbidden", first: 403, body: `{"code":"CONFLICT"}`, calls: 1, wantError: true},
		{name: "canceled backoff", first: 409, body: `{"code":"CONFLICT"}`, calls: 1, cancel: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			var correlationID string
			api := NewAPIClientWithAuth("token")
			api.BaseURL = "http://breakglass.test"
			api.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, debugSessionsBasePath+"/session/terminate", r.URL.Path)
				if calls == 1 {
					correlationID = r.Header.Get(CorrelationIDHeader)
					require.NotEmpty(t, correlationID)
				}
				require.Equal(t, correlationID, r.Header.Get(CorrelationIDHeader))
				if test.cancel {
					cancel()
				}
				status := test.first
				if calls > 1 {
					status = test.next
				}
				return testResponse(status, test.body), nil
			})}
			err := api.TerminateDebugSession(ctx, nil, "session")
			if test.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if test.cancel {
				require.ErrorIs(t, err, context.Canceled)
			}
			require.Equal(t, test.calls, calls)
		})
	}
}

func TestAPIClientListSessionsDecodesItemsEnvelope(t *testing.T) {
	var requestPath string
	client := NewAPIClientWithAuth("token")
	client.BaseURL = "http://breakglass.test"
	client.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requestPath = r.URL.Path
		return testResponse(http.StatusOK, `{"items":[{"spec":{"cluster":"dev","grantedGroup":"admin-group","user":"alice@example.com"}}],"total":1}`), nil
	})}

	sessions, err := client.ListSessions(context.Background())
	require.NoError(t, err)

	assert.Equal(t, sessionsBasePath, requestPath)
	require.Len(t, sessions, 1)
	assert.Equal(t, "dev", sessions[0].Spec.Cluster)
	assert.Equal(t, "admin-group", sessions[0].Spec.GrantedGroup)
	assert.Equal(t, "alice@example.com", sessions[0].Spec.User)
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
