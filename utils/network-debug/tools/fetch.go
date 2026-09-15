// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// fetch downloads one build input and verifies it before atomically publishing
// it at the requested path. It intentionally uses only the Go standard
// library; the pinned builder's build-only compiler packages never enter the
// runtime image.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxDownloadBytes = 128 << 20
const maxRedirectHops = 3
const maxAssetQueryBytes = 16 << 10

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var releaseAssetPath = regexp.MustCompile(`^/[^/]+/[^/]+/releases/download/[^/]+/[^/]+$`)

const githubReleaseHost = "github.com"

var githubAssetCDNHosts = map[string]string{
	"objects.githubusercontent.com":        "/github-production-release-asset/",
	"release-assets.githubusercontent.com": "/github-production-release-asset/",
}

func main() {
	if len(os.Args) != 4 {
		failf("usage: fetch URL OUTPUT SHA256")
	}
	rawURL, output, expected := os.Args[1], os.Args[2], os.Args[3]
	if !digestPattern.MatchString(expected) {
		failf("expected SHA256 must contain exactly 64 lowercase hexadecimal characters")
	}
	if err := fetch(rawURL, output, expected); err != nil {
		failf("%v", err)
	}
}

func fetch(rawURL, output, expected string) error {
	return fetchWithClient(newDownloadClient(), rawURL, output, expected)
}

func newDownloadClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Minute, CheckRedirect: redirectPolicy}
}

func fetchWithClient(client *http.Client, rawURL, output, expected string) error {
	if !digestPattern.MatchString(expected) {
		return fmt.Errorf("expected SHA256 must contain exactly 64 lowercase hexadecimal characters")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse request URL: %w", err)
	}
	if err := validateGitHubReleaseURL(parsed); err != nil {
		return fmt.Errorf("request URL: %w", err)
	}
	request, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP status %s", response.Status)
	}

	directory := filepath.Dir(output)
	temporary, err := os.CreateTemp(directory, ".verified-download-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = os.Remove(temporaryName) // #nosec G703 -- CreateTemp generated this path in the validated output directory.
	}()

	hash := sha256.New()
	limited := io.LimitReader(io.TeeReader(response.Body, hash), maxDownloadBytes+1)
	bytes, err := io.Copy(temporary, limited)
	if err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write download: %w", err)
	}
	if bytes > maxDownloadBytes {
		_ = temporary.Close()
		return fmt.Errorf("download exceeds %d-byte bound", maxDownloadBytes)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary output: %w", err)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expected {
		return fmt.Errorf("SHA256 mismatch: got %s, expected %s", actual, expected)
	}
	if err := os.Rename(temporaryName, output); err != nil { // #nosec G703 -- output is a validated filename in the selected output directory.
		return fmt.Errorf("publish verified output: %w", err)
	}
	return nil
}

func redirectPolicy(request *http.Request, via []*http.Request) error {
	if len(via) > maxRedirectHops {
		return fmt.Errorf("redirect limit exceeded (%d hops)", maxRedirectHops)
	}
	if err := validateGitHubAssetURL(request.URL); err != nil {
		return fmt.Errorf("redirect target: %w", err)
	}
	return nil
}

func validateGitHubReleaseURL(parsed *url.URL) error {
	if parsed == nil || parsed.Scheme != "https" {
		return fmt.Errorf("release URL must use HTTPS")
	}
	if parsed.User != nil {
		return fmt.Errorf("release URL must not contain userinfo")
	}
	if parsed.Port() != "" {
		return fmt.Errorf("release URL must not contain an explicit port")
	}
	if strings.ToLower(parsed.Hostname()) != githubReleaseHost {
		return fmt.Errorf("release URL host must be %s", githubReleaseHost)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("release URL must not contain a query or fragment")
	}
	if !releaseAssetPath.MatchString(parsed.Path) {
		return fmt.Errorf("release URL is not a GitHub release asset path")
	}
	return nil
}

func validateGitHubAssetURL(parsed *url.URL) error {
	if parsed == nil || parsed.Scheme != "https" {
		return fmt.Errorf("asset redirect must use HTTPS")
	}
	if parsed.User != nil {
		return fmt.Errorf("asset redirect must not contain userinfo")
	}
	if parsed.Port() != "" {
		return fmt.Errorf("asset redirect must not contain an explicit port")
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("asset redirect must not contain a fragment")
	}
	if err := validateGitHubAssetQuery(parsed.RawQuery); err != nil {
		return fmt.Errorf("asset redirect query: %w", err)
	}
	prefix, ok := githubAssetCDNHosts[strings.ToLower(parsed.Hostname())]
	if !ok {
		return fmt.Errorf("asset redirect host is not an approved GitHub CDN")
	}
	if !strings.HasPrefix(parsed.Path, prefix) {
		return fmt.Errorf("asset redirect path is not a GitHub release asset")
	}
	return nil
}

func validateGitHubAssetQuery(rawQuery string) error {
	// GitHub currently signs release assets with provider-specific query keys.
	// Validate only the transport-safe grammar and bounds here; key names and
	// values stay opaque so a signing-provider change does not break downloads.
	if rawQuery == "" {
		return fmt.Errorf("signed asset query must not be empty")
	}
	if len(rawQuery) > maxAssetQueryBytes {
		return fmt.Errorf("signed asset query exceeds %d-byte bound", maxAssetQueryBytes)
	}
	if strings.ContainsRune(rawQuery, ';') {
		return fmt.Errorf("signed asset query must use ampersand separators")
	}
	parts := strings.Split(rawQuery, "&")
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if part == "" {
			return fmt.Errorf("signed asset query contains an empty component")
		}
		separator := strings.IndexByte(part, '=')
		if separator <= 0 {
			return fmt.Errorf("signed asset query components must use key=value syntax")
		}
		key, err := url.QueryUnescape(part[:separator])
		if err != nil {
			return fmt.Errorf("decode signed asset query key: %w", err)
		}
		value, err := url.QueryUnescape(part[separator+1:])
		if err != nil {
			return fmt.Errorf("decode signed asset query value: %w", err)
		}
		if key == "" {
			return fmt.Errorf("signed asset query keys must not be empty")
		}
		if containsControl(key) || containsControl(value) {
			return fmt.Errorf("signed asset query must not contain control characters")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("signed asset query contains duplicate key %q", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func failf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "fetch: "+format+"\n", args...)
	os.Exit(2)
}
