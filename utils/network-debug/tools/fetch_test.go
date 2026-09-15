// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testReleaseURL = "https://github.com/cilium/pwru/releases/download/v1.0.12/pwru-linux-amd64.tar.gz"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type errorReadCloser struct{}

func (errorReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("synthetic body read failure")
}

func (errorReadCloser) Close() error {
	return nil
}

type repeatingReader struct {
	remaining int64
}

func (reader *repeatingReader) Read(buffer []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	count := int64(len(buffer))
	if count > reader.remaining {
		count = reader.remaining
	}
	for index := 0; index < int(count); index++ {
		buffer[index] = 'x'
	}
	reader.remaining -= count
	return int(count), nil
}

func clientReturning(status int, body io.ReadCloser) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Status:     http.StatusText(status),
			Body:       body,
			Header:     make(http.Header),
		}, nil
	})}
}

func newFetchTestClient(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.StartTLS()
	t.Cleanup(server.Close)

	// Route every approved test hostname to the local TLS server. Production
	// uses the default transport, so this cannot widen the runtime allowlist.
	transport := &http.Transport{
		// #nosec G402 -- the test server uses a generated certificate and never
		// carries production credentials or data.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
	}
	client := &http.Client{Transport: transport, Timeout: time.Minute, CheckRedirect: redirectPolicy}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestFetchAllowsGitHubReleaseCDNRedirect(t *testing.T) {
	body := []byte("verified release archive")
	hash := sha256.Sum256(body)
	client := newFetchTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Host {
		case "github.com":
			header := "https://release-assets.githubusercontent.com/github-production-release-asset/cilium/pwru/archive.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=opaque%2Fcredential&X-Amz-Date=20260828T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=opaque%2Bsignature%3D"
			http.Redirect(writer, request, header, http.StatusFound)
		case "release-assets.githubusercontent.com":
			_, _ = writer.Write(body)
		default:
			http.NotFound(writer, request)
		}
	}))

	output := filepath.Join(t.TempDir(), "pwru.tar.gz")
	if err := fetchWithClient(client, testReleaseURL, output, hex.EncodeToString(hash[:])); err != nil {
		t.Fatalf("fetchWithClient() returned error: %v", err)
	}
	if actual, err := os.ReadFile(output); err != nil || string(actual) != string(body) {
		t.Fatalf("published output = %q, %v; want %q", actual, err, body)
	}
}

func TestFetchAllowsGitHubObjectsCDNRedirect(t *testing.T) {
	body := []byte("verified object archive")
	hash := sha256.Sum256(body)
	client := newFetchTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host == "github.com" {
			http.Redirect(writer, request, "https://objects.githubusercontent.com/github-production-release-asset/cilium/pwru/archive.tar.gz?sig=opaque", http.StatusFound)
			return
		}
		if request.Host == "objects.githubusercontent.com" {
			_, _ = writer.Write(body)
			return
		}
		http.NotFound(writer, request)
	}))

	output := filepath.Join(t.TempDir(), "pwru.tar.gz")
	if err := fetchWithClient(client, testReleaseURL, output, hex.EncodeToString(hash[:])); err != nil {
		t.Fatalf("fetchWithClient() returned error: %v", err)
	}
}

func TestRedirectPolicyAllowsThreeAndRejectsFourth(t *testing.T) {
	assetURL, err := url.Parse("https://release-assets.githubusercontent.com/github-production-release-asset/cilium/pwru/archive.tar.gz?sig=opaque")
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{URL: assetURL}

	// net/http includes the initial request in via. Therefore len(via)==3 is
	// the third redirect and remains allowed; the fourth has len(via)==4.
	if err := redirectPolicy(request, make([]*http.Request, maxRedirectHops)); err != nil {
		t.Fatalf("third redirect rejected: %v", err)
	}
	if err := redirectPolicy(request, make([]*http.Request, maxRedirectHops+1)); err == nil {
		t.Fatal("fourth redirect was accepted")
	}
}

func TestFetchRejectsUnsafeRedirects(t *testing.T) {
	validCDNPath := "https://release-assets.githubusercontent.com/github-production-release-asset/cilium/pwru/archive.tar.gz"
	tests := []struct {
		name   string
		target string
	}{
		{name: "foreign host", target: "https://example.invalid/github-production-release-asset/archive.tar.gz"},
		{name: "downgrade", target: "http://release-assets.githubusercontent.com/github-production-release-asset/archive.tar.gz"},
		{name: "userinfo", target: "https://user:password@release-assets.githubusercontent.com/github-production-release-asset/archive.tar.gz"},
		{name: "explicit port", target: "https://release-assets.githubusercontent.com:8443/github-production-release-asset/archive.tar.gz"},
		{name: "IP literal", target: "https://127.0.0.1/github-production-release-asset/archive.tar.gz"},
		{name: "foreign path", target: "https://release-assets.githubusercontent.com/not-a-release-asset/archive.tar.gz"},
		{name: "missing signed query", target: validCDNPath},
		{name: "fragment", target: validCDNPath + "?sig=one#fragment"},
		{name: "empty query component", target: validCDNPath + "?sig=one&&next=two"},
		{name: "bare query component", target: validCDNPath + "?sig"},
		{name: "empty query key", target: validCDNPath + "?=value"},
		{name: "malformed escape", target: validCDNPath + "?sig=%zz"},
		{name: "control character", target: validCDNPath + "?sig=one%0Avalue"},
		{name: "duplicate decoded key", target: validCDNPath + "?sig=one&%73ig=two"},
		{name: "oversized query", target: validCDNPath + "?sig=" + strings.Repeat("x", maxAssetQueryBytes)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newFetchTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				http.Redirect(writer, request, test.target, http.StatusFound)
			}))
			output := filepath.Join(t.TempDir(), "pwru.tar.gz")
			if err := fetchWithClient(client, testReleaseURL, output, strings.Repeat("0", 64)); err == nil {
				t.Fatalf("unsafe redirect %q was accepted", test.target)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("unsafe redirect created output: %v", err)
			}
		})
	}
}

func TestFetchRejectsInitialURLSurprises(t *testing.T) {
	for _, rawURL := range []string{
		testReleaseURL + "?unexpected=true",
		testReleaseURL + "#fragment",
		"http://github.com/cilium/pwru/releases/download/v1.0.12/pwru-linux-amd64.tar.gz",
		"https://github.com/cilium/pwru/archive/main.tar.gz",
	} {
		t.Run(rawURL, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "pwru.tar.gz")
			if err := fetchWithClient(&http.Client{}, rawURL, output, strings.Repeat("0", 64)); err == nil {
				t.Fatalf("unsafe initial URL %q was accepted", rawURL)
			}
		})
	}
}

func TestFetchRejectsRedirectLoopsAfterBoundedHops(t *testing.T) {
	client := newFetchTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "https://release-assets.githubusercontent.com/github-production-release-asset/cilium/pwru/archive.tar.gz?loop=true", http.StatusFound)
	}))
	output := filepath.Join(t.TempDir(), "pwru.tar.gz")
	if err := fetchWithClient(client, testReleaseURL, output, strings.Repeat("0", 64)); err == nil {
		t.Fatal("redirect loop was accepted")
	}
}

func TestFetchRejectsIncorrectDigestWithoutReplacingOutput(t *testing.T) {
	client := newFetchTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("untrusted release archive"))
	}))

	output := filepath.Join(t.TempDir(), "pwru.tar.gz")
	original := []byte("previous verified output")
	if err := os.WriteFile(output, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := fetchWithClient(client, testReleaseURL, output, strings.Repeat("0", 64)); err == nil {
		t.Fatal("fetchWithClient() accepted an incorrect digest")
	}
	if actual, err := os.ReadFile(output); err != nil || string(actual) != string(original) {
		t.Fatalf("existing output = %q, %v; want %q", actual, err, original)
	}
}

func TestFetchRejectsInvalidInputBeforeNetwork(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid input reached the network")
		return nil, nil
	})}
	for _, test := range []struct {
		name     string
		rawURL   string
		expected string
	}{
		{name: "invalid digest", rawURL: testReleaseURL, expected: "not-a-digest"},
		{name: "invalid URL escape", rawURL: "https://github.com/cilium/pwru/releases/download/v1.0.12/pwru-linux-amd64.tar.gz%zz", expected: strings.Repeat("0", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := fetchWithClient(client, test.rawURL, filepath.Join(t.TempDir(), "pwru.tar.gz"), test.expected); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}
	if err := validateGitHubReleaseURL(nil); err == nil {
		t.Fatal("nil release URL was accepted")
	}
	if err := validateGitHubAssetURL(nil); err == nil {
		t.Fatal("nil asset URL was accepted")
	}
}

func TestNewDownloadClientEnforcesTimeoutAndRedirectPolicy(t *testing.T) {
	client := newDownloadClient()
	if client.Timeout != 5*time.Minute {
		t.Fatalf("download timeout = %s, want five minutes", client.Timeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("download client has no redirect policy")
	}
}

func TestFetchRejectsNetworkAndHTTPFailures(t *testing.T) {
	validDigest := strings.Repeat("0", 64)
	networkClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("synthetic network failure")
	})}
	if err := fetchWithClient(networkClient, testReleaseURL, filepath.Join(t.TempDir(), "pwru.tar.gz"), validDigest); err == nil {
		t.Fatal("network failure was accepted")
	}
	statusClient := clientReturning(http.StatusBadGateway, io.NopCloser(strings.NewReader("upstream failure")))
	if err := fetchWithClient(statusClient, testReleaseURL, filepath.Join(t.TempDir(), "pwru.tar.gz"), validDigest); err == nil {
		t.Fatal("non-success HTTP status was accepted")
	}
}

func TestFetchRejectsOutputAndBodyFailures(t *testing.T) {
	body := []byte("valid body")
	hash := sha256.Sum256(body)
	client := clientReturning(http.StatusOK, io.NopCloser(strings.NewReader(string(body))))
	missingParent := filepath.Join(t.TempDir(), "missing", "pwru.tar.gz")
	if err := fetchWithClient(client, testReleaseURL, missingParent, hex.EncodeToString(hash[:])); err == nil {
		t.Fatal("missing output parent was accepted")
	}

	readFailureClient := clientReturning(http.StatusOK, errorReadCloser{})
	if err := fetchWithClient(readFailureClient, testReleaseURL, filepath.Join(t.TempDir(), "pwru.tar.gz"), hex.EncodeToString(hash[:])); err == nil {
		t.Fatal("body read failure was accepted")
	}
}

func TestFetchRejectsOversizedDownload(t *testing.T) {
	client := clientReturning(http.StatusOK, io.NopCloser(&repeatingReader{remaining: maxDownloadBytes + 1}))
	if err := fetchWithClient(client, testReleaseURL, filepath.Join(t.TempDir(), "pwru.tar.gz"), strings.Repeat("0", 64)); err == nil {
		t.Fatal("oversized download was accepted")
	}
}

func TestFetchRejectsRenameFailure(t *testing.T) {
	body := []byte("valid body")
	hash := sha256.Sum256(body)
	outputDirectory := t.TempDir()
	client := clientReturning(http.StatusOK, io.NopCloser(strings.NewReader(string(body))))
	if err := fetchWithClient(client, testReleaseURL, outputDirectory, hex.EncodeToString(hash[:])); err == nil {
		t.Fatal("directory output target was accepted")
	}
}
