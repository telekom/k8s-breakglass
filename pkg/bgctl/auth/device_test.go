package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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

	_ = os.Setenv("BGCTL_NO_BROWSER", "true")
	t.Cleanup(func() { _ = os.Unsetenv("BGCTL_NO_BROWSER") })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := DeviceCodeLogin(ctx, OIDCConfig{Authority: server.URL, ClientID: "bgctl", GrantType: "device-code"})
	require.NoError(t, err)
	require.Equal(t, "token", res.Token.AccessToken)
}
