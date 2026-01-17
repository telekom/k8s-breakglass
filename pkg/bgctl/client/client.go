package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type Client struct {
	baseURL   *url.URL
	token     string
	http      *http.Client
	userAgent string
}

type Option func(*Client) error

func New(opts ...Option) (*Client, error) {
	c := &Client{
		http:      &http.Client{Timeout: 30 * time.Second},
		userAgent: "bgctl",
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	if c.baseURL == nil {
		return nil, errors.New("server is required")
	}
	return c, nil
}

func WithServer(server string) Option {
	return func(c *Client) error {
		if server == "" {
			return errors.New("server is required")
		}
		parsed, err := url.Parse(server)
		if err != nil {
			return fmt.Errorf("invalid server: %w", err)
		}
		c.baseURL = parsed
		return nil
	}
}

func WithToken(token string) Option {
	return func(c *Client) error {
		c.token = token
		return nil
	}
}

func WithUserAgent(userAgent string) Option {
	return func(c *Client) error {
		c.userAgent = userAgent
		return nil
	}
}

func WithTLSConfig(caFile string, insecureSkipTLSVerify bool) Option {
	return func(c *Client) error {
		tlsConfig, err := loadTLSConfig(caFile, insecureSkipTLSVerify)
		if err != nil {
			return err
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		c.http = &http.Client{Transport: transport, Timeout: 30 * time.Second}
		return nil
	}
}

func loadTLSConfig(caFile string, insecure bool) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}
	if caFile == "" {
		return tlsConfig, nil
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(data); !ok {
		return nil, errors.New("failed to parse CA file")
	}
	tlsConfig.RootCAs = pool
	return tlsConfig, nil
}

func (c *Client) do(ctx context.Context, method, endpoint string, body any, out any) error {
	fullURL := *c.baseURL
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}
	fullURL.Path = path.Join(fullURL.Path, parsedEndpoint.Path)
	if parsedEndpoint.RawQuery != "" {
		fullURL.RawQuery = parsedEndpoint.RawQuery
	}

	var payload io.Reader
	if body != nil {
		bytesBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		payload = bytes.NewReader(bytesBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL.String(), payload)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		return decodeError(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func decodeError(resp *http.Response) error {
	var apiErr struct {
		Error string `json:"error"`
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) > 0 {
		_ = json.Unmarshal(body, &apiErr)
	}
	msg := strings.TrimSpace(apiErr.Error)
	if msg == "" {
		msg = strings.TrimSpace(string(body))
	}
	if msg == "" {
		msg = resp.Status
	}
	return &HTTPError{StatusCode: resp.StatusCode, Message: msg}
}

type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("request failed (%d): %s", e.StatusCode, e.Message)
}
