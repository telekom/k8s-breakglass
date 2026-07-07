package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDeviceCodeLogin(t *testing.T) {
	var tokenCalls int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token_endpoint":                server.URL + "/token",
				"device_authorization_endpoint": server.URL + "/device",
			})
		case "/device":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":      "abc",
				"user_code":        "XYZ",
				"verification_uri": "https://example.com",
				"expires_in":       60,
				"interval":         1,
			})
		case "/token":
			call := atomic.AddInt32(&tokenCalls, 1)
			if call == 1 {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "token",
				"refresh_token": "refresh",
				"token_type":    "Bearer",
				"expires_in":    60,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Setenv("BGCTL_NO_BROWSER", "true")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := DeviceCodeLogin(ctx, OIDCConfig{Authority: server.URL, ClientID: "bgctl", GrantType: "device-code"})
	require.NoError(t, err)
	require.Equal(t, "token", res.Token.AccessToken)
}

func TestDeviceCodeLoginCancelsDuringPollingWait(t *testing.T) {
	var tokenCalls int32
	var closeTokenResponded sync.Once
	tokenResponded := make(chan struct{})
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token_endpoint":                server.URL + "/token",
				"device_authorization_endpoint": server.URL + "/device",
			})
		case "/device":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":      "abc",
				"user_code":        "XYZ",
				"verification_uri": "https://example.com",
				"expires_in":       60,
				"interval":         1,
			})
		case "/token":
			atomic.AddInt32(&tokenCalls, 1)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			closeTokenResponded.Do(func() { close(tokenResponded) })
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Setenv("BGCTL_NO_BROWSER", "true")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := DeviceCodeLogin(ctx, OIDCConfig{Authority: server.URL, ClientID: "bgctl", GrantType: "device-code"})
		done <- err
	}()

	select {
	case <-tokenResponded:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial authorization_pending response")
	}

	start := time.Now()
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		require.Less(t, time.Since(start), 500*time.Millisecond)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("device login did not stop promptly after context cancellation")
	}
	require.Equal(t, int32(1), atomic.LoadInt32(&tokenCalls))
}

func TestRequestDeviceCodeUsesRequestContext(t *testing.T) {
	requestStarted := make(chan struct{})
	contentTypeSeen := make(chan string, 1)
	var closeRequestStarted sync.Once
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			contentTypeSeen <- req.Header.Get("Content-Type")
			closeRequestStarted.Do(func() { close(requestStarted) })
			<-req.Context().Done()
			return nil, req.Context().Err()
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := requestDeviceCode(ctx, client, "https://oidc.example/device", OIDCConfig{ClientID: "bgctl"})
		done <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for device authorization request")
	}
	require.Equal(t, "application/x-www-form-urlencoded", <-contentTypeSeen)

	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		require.True(t, errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled"), "expected context cancellation, got %v", err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("device authorization request did not stop promptly after context cancellation")
	}
}

func TestRequestDeviceCodeTruncatesOversizedErrorBody(t *testing.T) {
	body := strings.Repeat("a", oidcErrorBodyLimit) + "TAIL"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	_, err := requestDeviceCode(context.Background(), server.Client(), server.URL, OIDCConfig{ClientID: "bgctl"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "device authorization failed")
	require.Contains(t, err.Error(), "truncated after 4096 bytes")
	require.NotContains(t, err.Error(), "TAIL")
}

func TestDiscoverOIDCEndpointsWrapsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token_endpoint":"` + strings.Repeat("a", oidcJSONBodyLimit) + `"}`))
	}))
	defer server.Close()

	_, err := discoverOIDCEndpoints(context.Background(), server.Client(), server.URL)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode OIDC discovery response")
	require.Contains(t, err.Error(), server.URL+"/.well-known/openid-configuration")
	require.Contains(t, err.Error(), "oidc json response exceeds 1048576 bytes")
}

func TestRequestDeviceCodeWrapsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"device_code":"` + strings.Repeat("a", oidcJSONBodyLimit) + `"}`))
	}))
	defer server.Close()

	_, err := requestDeviceCode(context.Background(), server.Client(), server.URL, OIDCConfig{ClientID: "bgctl"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode device authorization response")
	require.Contains(t, err.Error(), server.URL)
	require.Contains(t, err.Error(), "oidc json response exceeds 1048576 bytes")
}

func TestPollDeviceTokenRejectsOversizedSuccessBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"` + strings.Repeat("a", oidcJSONBodyLimit) + `"}`))
	}))
	defer server.Close()

	_, err := pollDeviceToken(context.Background(), server.Client(), server.URL, OIDCConfig{ClientID: "bgctl"}, "abc")
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode device token response")
	require.Contains(t, err.Error(), server.URL)
	require.Contains(t, err.Error(), "oidc json response exceeds 1048576 bytes")
}

func TestPollDeviceTokenWrapsInvalidErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("{not-json"))
	}))
	defer server.Close()

	_, err := pollDeviceToken(context.Background(), server.Client(), server.URL, OIDCConfig{ClientID: "bgctl"}, "abc")
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode device token error response")
	require.Contains(t, err.Error(), server.URL)
	require.Contains(t, err.Error(), "HTTP 400")
}

func TestPollDeviceTokenIncludesErrorDescription(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "access_denied",
			"error_description": "device login was denied",
		})
	}))
	defer server.Close()

	_, err := pollDeviceToken(context.Background(), server.Client(), server.URL, OIDCConfig{ClientID: "bgctl"}, "abc")
	require.Error(t, err)
	require.Contains(t, err.Error(), "device token error: access_denied: device login was denied")
}
