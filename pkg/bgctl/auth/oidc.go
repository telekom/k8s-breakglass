package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	Authority       string
	ClientID        string
	ClientSecret    string
	Scopes          []string
	GrantType       string
	CAFile          string
	InsecureSkipTLS bool
	ExtraAuthParams map[string]string
}

type LoginResult struct {
	Token   *oauth2.Token
	IDToken string
}

type OAuthConfigResult struct {
	OAuthConfig oauth2.Config
	Client      *http.Client
}

func BuildOAuthConfig(ctx context.Context, cfg OIDCConfig, redirectURL string) (*OAuthConfigResult, error) {
	if cfg.Authority == "" || cfg.ClientID == "" {
		return nil, errors.New("authority and client-id are required")
	}
	httpClient, err := newHTTPClient(cfg.CAFile, cfg.InsecureSkipTLS)
	if err != nil {
		return nil, err
	}
	ctx = oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(ctx, cfg.Authority)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider: %w", err)
	}
	scopes := []string{oidc.ScopeOpenID, "email", "profile"}
	if len(cfg.Scopes) > 0 {
		scopes = cfg.Scopes
	}
	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}
	return &OAuthConfigResult{OAuthConfig: oauthCfg, Client: httpClient}, nil
}

func Login(ctx context.Context, cfg OIDCConfig) (*LoginResult, error) {
	if cfg.GrantType == "" {
		cfg.GrantType = "authorization-code"
	}
	if cfg.GrantType == "device-code" {
		return DeviceCodeLogin(ctx, cfg)
	}
	if cfg.GrantType == "client-credentials" {
		return ClientCredentialsLogin(ctx, cfg)
	}
	if cfg.GrantType != "authorization-code" {
		return nil, fmt.Errorf("unsupported grant type: %s", cfg.GrantType)
	}
	if cfg.Authority == "" || cfg.ClientID == "" {
		return nil, errors.New("authority and client-id are required")
	}

	codeVerifier, codeChallenge, err := newPKCEPair()
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start callback listener: %w", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	redirectURL := fmt.Sprintf("http://%s/callback", listener.Addr().String())
	oauthResult, err := BuildOAuthConfig(ctx, cfg, redirectURL)
	if err != nil {
		return nil, err
	}
	oauthCfg := oauthResult.OAuthConfig

	state, err := randomToken(24)
	if err != nil {
		return nil, err
	}

	authOpts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	for k, v := range cfg.ExtraAuthParams {
		authOpts = append(authOpts, oauth2.SetAuthURLParam(k, v))
	}
	authURL := oauthCfg.AuthCodeURL(state, authOpts...)

	resultCh := make(chan *LoginResult, 1)
	errCh := make(chan error, 1)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			if r.URL.Query().Get("state") != state {
				errCh <- errors.New("invalid state in callback")
				http.Error(w, "invalid state", http.StatusBadRequest)
				return
			}
			code := r.URL.Query().Get("code")
			if code == "" {
				errCh <- errors.New("missing code in callback")
				http.Error(w, "missing code", http.StatusBadRequest)
				return
			}
			token, err := oauthCfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
			if err != nil {
				errCh <- fmt.Errorf("token exchange failed: %w", err)
				http.Error(w, "token exchange failed", http.StatusInternalServerError)
				return
			}
			idToken, _ := token.Extra("id_token").(string)
			_, _ = fmt.Fprintln(w, "Authentication complete. You can close this window.")
			resultCh <- &LoginResult{Token: token, IDToken: idToken}
		}),
	}

	go func() {
		_ = server.Serve(listener)
	}()

	_, _ = fmt.Fprintf(os.Stdout, "Open the following URL in your browser:\n%s\n", authURL)
	_ = openBrowser(authURL)

	select {
	case <-ctx.Done():
		_ = server.Close()
		return nil, ctx.Err()
	case err := <-errCh:
		_ = server.Close()
		return nil, err
	case result := <-resultCh:
		_ = server.Close()
		return result, nil
	}
}

func newPKCEPair() (string, string, error) {
	verifier, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

func randomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if cmd == nil {
		return errors.New("no browser command available")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

func newHTTPClient(caFile string, insecure bool) (*http.Client, error) {
	transport, err := buildTransport(caFile, insecure)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

func buildTransport(caFile string, insecure bool) (http.RoundTripper, error) {
	tlsConfig, err := loadTLSConfig(caFile, insecure)
	if err != nil {
		return nil, err
	}
	return &http.Transport{TLSClientConfig: tlsConfig}, nil
}

func loadTLSConfig(caFile string, insecure bool) (*tls.Config, error) {
	if caFile == "" && !insecure {
		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	}
	certPool, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure,
		RootCAs:            certPool,
	}, nil
}

func loadCertPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(data); !ok {
		return nil, errors.New("failed to parse CA file")
	}
	return pool, nil
}

func ResolveClientSecret(secret, secretEnv, secretFile string) (string, error) {
	if secret != "" {
		return secret, nil
	}
	if secretEnv != "" {
		value := strings.TrimSpace(os.Getenv(secretEnv))
		if value == "" {
			return "", fmt.Errorf("client secret env var not set: %s", secretEnv)
		}
		return value, nil
	}
	if secretFile != "" {
		bytes, err := os.ReadFile(secretFile)
		if err != nil {
			return "", fmt.Errorf("failed to read client secret file: %w", err)
		}
		return strings.TrimSpace(string(bytes)), nil
	}
	return "", nil
}
