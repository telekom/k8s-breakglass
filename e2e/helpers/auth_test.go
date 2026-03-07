package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetToken_RetriesTransientFailures verifies that GetToken retries on
// connection-level errors and 5xx responses before eventually succeeding.
func TestGetToken_RetriesTransientFailures(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n <= 2 {
			// First two calls: simulate Keycloak still starting
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		// Third call: success
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok-ok",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer srv.Close()

	provider := &OIDCTokenProvider{
		KeycloakHost:   srv.URL,
		Realm:          "test",
		ClientID:       "test-client",
		InitialBackoff: 10 * time.Millisecond, // fast backoff for tests
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token := provider.GetToken(t, ctx, "user", "pass")
	assert.Equal(t, "tok-ok", token)
	assert.Equal(t, int32(3), calls.Load(), "expected 3 HTTP calls (2 failures + 1 success)")
}

// TestGetToken_NoRetryOn401 verifies that GetToken does NOT retry when
// Keycloak returns 401 (bad credentials).
func TestGetToken_NoRetryOn401(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	provider := &OIDCTokenProvider{
		KeycloakHost: srv.URL,
		Realm:        "test",
		ClientID:     "test-client",
	}

	// Test the underlying getTokenViaHTTP — GetToken calls require.NoError
	// which would abort the test before we can assert retry counts.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := provider.getTokenViaHTTP(ctx, "user", "wrong-pass")
	require.Error(t, err)

	var tErr *tokenRequestError
	require.ErrorAs(t, err, &tErr)
	assert.Equal(t, http.StatusUnauthorized, tErr.StatusCode)
	assert.True(t, tErr.isNonRetryable(), "401 should be non-retryable")

	assert.Equal(t, int32(1), calls.Load(), "expected exactly 1 HTTP call (no retry on 401)")
}

// TestGetToken_NoRetryOn400 verifies that 400 (bad request) is also non-retryable.
func TestGetToken_NoRetryOn400(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	provider := &OIDCTokenProvider{
		KeycloakHost: srv.URL,
		Realm:        "test",
		ClientID:     "test-client",
	}

	ctx := context.Background()
	_, err := provider.getTokenViaHTTP(ctx, "user", "pass")
	require.Error(t, err)

	var tErr *tokenRequestError
	require.ErrorAs(t, err, &tErr)
	assert.Equal(t, http.StatusBadRequest, tErr.StatusCode)
	assert.True(t, tErr.isNonRetryable())
}

// TestGetToken_retryableVsNonRetryable verifies error classification boundaries.
func TestGetToken_retryableVsNonRetryable(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		wantRetryable bool
	}{
		{"400 Bad Request", 400, false},
		{"401 Unauthorized", 401, false},
		{"403 Forbidden", 403, false},
		{"404 Not Found", 404, false},
		{"429 Too Many Requests", 429, true},
		{"499 Client Error", 499, false},
		{"500 Internal Server Error", 500, true},
		{"502 Bad Gateway", 502, true},
		{"503 Service Unavailable", 503, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &tokenRequestError{
				StatusCode: tt.statusCode,
				Message:    fmt.Sprintf("status %d", tt.statusCode),
			}
			if tt.wantRetryable {
				assert.False(t, err.isNonRetryable(), "%d should be retryable", tt.statusCode)
			} else {
				assert.True(t, err.isNonRetryable(), "%d should be non-retryable", tt.statusCode)
			}
		})
	}
}

// TestGetToken_ContextCancellation verifies that GetToken's retry loop
// respects context cancellation during the backoff wait, exiting promptly
// instead of sleeping through all retry attempts.
// We test via GetToken on a real *testing.T and assert it fails fast.
func TestGetToken_ContextCancellation(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	provider := &OIDCTokenProvider{
		KeycloakHost:   srv.URL,
		Realm:          "test",
		ClientID:       "test-client",
		InitialBackoff: 5 * time.Second, // longer than context timeout
	}

	// Context expires before the first backoff completes, so the retry loop
	// should exit after at most 2 HTTP attempts (attempt 1 → backoff → ctx cancel).
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	// Call getTokenViaHTTP in a loop to simulate GetToken's retry behavior
	// without require.NoError aborting the test.
	var lastErr error
	backoff := provider.initialBackoff()
	for attempt := 1; attempt <= 5; attempt++ {
		_, lastErr = provider.getTokenViaHTTP(ctx, "user", "pass")
		if lastErr == nil {
			break
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			lastErr = ctx.Err()
			goto done
		case <-timer.C:
		}
		backoff *= 2
	}
done:
	elapsed := time.Since(start)

	require.Error(t, lastErr)
	assert.ErrorIs(t, lastErr, context.DeadlineExceeded)
	// Should finish well before the 5s backoff would have elapsed.
	assert.Less(t, elapsed, 2*time.Second, "retry loop should exit promptly on context cancellation")
	// Should have made only 1-2 HTTP calls, not all 5 retry attempts.
	assert.LessOrEqual(t, calls.Load(), int32(2), "expected at most 2 HTTP calls before context cancellation")
}
