package auth

import (
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
				time.Sleep(interval)
				continue
			}
			if errors.Is(err, errSlowDown) {
				interval += 5 * time.Second
				time.Sleep(interval)
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
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discovery failed: %s", string(body))
	}
	var discovery oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
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
	resp, err := client.PostForm(endpoint, values)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device authorization failed: %s", string(body))
	}
	var payload deviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func pollDeviceToken(ctx context.Context, client *http.Client, endpoint string, cfg OIDCConfig, deviceCode string) (*tokenResponse, error) {
	values := url.Values{}
	values.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	values.Set("device_code", deviceCode)
	values.Set("client_id", cfg.ClientID)
	resp, err := client.PostForm(endpoint, values)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	var payload tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Error != "" {
		switch payload.Error {
		case "authorization_pending":
			return nil, errAuthorizationPending
		case "slow_down":
			return nil, errSlowDown
		default:
			return nil, fmt.Errorf("device token error: %s", payload.Error)
		}
	}
	return &payload, nil
}
