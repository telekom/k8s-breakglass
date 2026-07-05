package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	oidcErrorBodyLimit = 4 * 1024
	oidcJSONBodyLimit  = 1 * 1024 * 1024
)

type oidcDiscovery struct {
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

func DeviceCodeLogin(ctx context.Context, cfg OIDCConfig) (*LoginResult, error) {
	if cfg.Authority == "" || cfg.ClientID == "" {
		return nil, errors.New("authority and client-id are required")
	}
	client, err := newHTTPClient(cfg.CAFile, cfg.InsecureSkipTLS)
	if err != nil {
		return nil, err
	}
	endpoints, err := discoverOIDCEndpoints(ctx, client, cfg.Authority)
	if err != nil {
		return nil, err
	}
	if endpoints.DeviceAuthorizationEndpoint == "" {
		return nil, errors.New("device authorization endpoint not advertised")
	}
	if endpoints.TokenEndpoint == "" {
		return nil, errors.New("token endpoint not advertised")
	}

	deviceResp, err := requestDeviceCode(ctx, client, endpoints.DeviceAuthorizationEndpoint, cfg)
	if err != nil {
		return nil, err
	}

	verificationURL := deviceResp.VerificationURIComplete
	if verificationURL == "" {
		verificationURL = deviceResp.VerificationURI
	}

	fmt.Printf("Visit %s and enter code: %s\n", deviceResp.VerificationURI, deviceResp.UserCode)
	if verificationURL != "" && !strings.EqualFold(os.Getenv("BGCTL_NO_BROWSER"), "true") {
		_ = openBrowser(verificationURL)
	}

	interval := time.Duration(deviceResp.Interval) * time.Second
	if interval == 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)

	for {
		if time.Now().After(deadline) {
			return nil, errors.New("device code expired")
		}
		tokenResp, err := pollDeviceToken(ctx, client, endpoints.TokenEndpoint, cfg, deviceResp.DeviceCode)
		if err != nil {
			if errors.Is(err, errAuthorizationPending) {
				if err := waitForDevicePoll(ctx, interval); err != nil {
					return nil, err
				}
				continue
			}
			if errors.Is(err, errSlowDown) {
				interval += 5 * time.Second
				if err := waitForDevicePoll(ctx, interval); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		return &LoginResult{Token: &oauth2.Token{
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			TokenType:    tokenResp.TokenType,
			Expiry:       expiry,
		}, IDToken: tokenResp.IDToken}, nil
	}
}

var (
	errAuthorizationPending = errors.New("authorization pending")
	errSlowDown             = errors.New("slow down")
)

func discoverOIDCEndpoints(ctx context.Context, client *http.Client, authority string) (*oidcDiscovery, error) {
	trimmed := strings.TrimRight(authority, "/")
	url := trimmed + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("discovery failed: %s", readOIDCErrorBody(resp.Body))
	}
	var discovery oidcDiscovery
	if err := decodeLimitedJSON(resp.Body, &discovery); err != nil {
		return nil, err
	}
	return &discovery, nil
}

func requestDeviceCode(ctx context.Context, client *http.Client, endpoint string, cfg OIDCConfig) (*deviceCodeResponse, error) {
	values := url.Values{}
	values.Set("client_id", cfg.ClientID)
	if len(cfg.Scopes) > 0 {
		values.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	resp, err := postFormWithContext(ctx, client, endpoint, values)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("device authorization failed: %s", readOIDCErrorBody(resp.Body))
	}
	var payload deviceCodeResponse
	if err := decodeLimitedJSON(resp.Body, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func pollDeviceToken(ctx context.Context, client *http.Client, endpoint string, cfg OIDCConfig, deviceCode string) (*tokenResponse, error) {
	values := url.Values{}
	values.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	values.Set("device_code", deviceCode)
	values.Set("client_id", cfg.ClientID)
	resp, err := postFormWithContext(ctx, client, endpoint, values)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	var payload tokenResponse
	if resp.StatusCode >= 400 {
		body, truncated, err := readLimitedBody(resp.Body, oidcErrorBodyLimit)
		if err != nil {
			return nil, err
		}
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&payload); err != nil {
			return nil, fmt.Errorf("device token failed: HTTP %d: %s", resp.StatusCode, formatLimitedBody(body, truncated, oidcErrorBodyLimit))
		}
		if err := deviceTokenPayloadError(payload); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("device token failed: HTTP %d: %s", resp.StatusCode, formatLimitedBody(body, truncated, oidcErrorBodyLimit))
	}
	if err := decodeLimitedJSON(resp.Body, &payload); err != nil {
		return nil, err
	}
	if err := deviceTokenPayloadError(payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func deviceTokenPayloadError(payload tokenResponse) error {
	if payload.Error != "" {
		switch payload.Error {
		case "authorization_pending":
			return errAuthorizationPending
		case "slow_down":
			return errSlowDown
		default:
			if description := strings.TrimSpace(payload.ErrorDesc); description != "" {
				return fmt.Errorf("device token error: %s: %s", payload.Error, description)
			}
			return fmt.Errorf("device token error: %s", payload.Error)
		}
	}
	return nil
}

func postFormWithContext(ctx context.Context, client *http.Client, endpoint string, values url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return client.Do(req)
}

func waitForDevicePoll(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func readOIDCErrorBody(body io.Reader) string {
	data, truncated, err := readLimitedBody(body, oidcErrorBodyLimit)
	if err != nil {
		return fmt.Sprintf("failed to read response body: %v", err)
	}
	return formatLimitedBody(data, truncated, oidcErrorBodyLimit)
}

func decodeLimitedJSON(body io.Reader, target interface{}) error {
	return decodeLimitedJSONWithLimit(body, target, oidcJSONBodyLimit)
}

func decodeLimitedJSONWithLimit(body io.Reader, target interface{}, limit int64) error {
	data, truncated, err := readLimitedBody(body, limit)
	if err != nil {
		return err
	}
	if truncated {
		return fmt.Errorf("oidc json response exceeds %d bytes", limit)
	}
	return json.NewDecoder(bytes.NewReader(data)).Decode(target)
}

func readLimitedBody(body io.Reader, limit int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

func formatLimitedBody(data []byte, truncated bool, limit int64) string {
	text := strings.TrimSpace(string(data))
	if text == "" {
		text = "<empty response body>"
	}
	if truncated {
		return fmt.Sprintf("%s... (truncated after %d bytes)", text, limit)
	}
	return text
}
