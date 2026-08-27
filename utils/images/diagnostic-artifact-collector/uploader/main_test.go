// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
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

func TestUploadUsesBoundedPUTAndTokenWithoutLoggingSecrets(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	oldFactory := newUploadHTTPClient
	defer func() { artifactPath, readyPath, newUploadHTTPClient = oldPath, oldReady, oldFactory }()
	artifactPath, readyPath = path, ready

	var method, auth, body string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		payload, _ := io.ReadAll(request.Body)
		method, auth, body = request.Method, request.Header.Get("Authorization"), string(payload)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	newUploadHTTPClient = func() *http.Client {
		return server.Client()
	}
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", server.URL+"/exact-object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")

	if err := upload(context.Background()); err != nil {
		t.Fatalf("upload() error = %v", err)
	}
	if method != http.MethodPut || auth != "Bearer one-time-token" || body != "archive-bytes" {
		t.Fatalf("unexpected request: method=%q auth=%q body=%q", method, auth, body)
	}
}

func TestUploadHTTPClientIgnoresAmbientCABundleOverrides(t *testing.T) {
	pinnedServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer pinnedServer.Close()
	alternateServer := newIndependentTLSServer(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer alternateServer.Close()

	bundleDir := t.TempDir()
	pinnedBundle := filepath.Join(bundleDir, "pinned.pem")
	writeCertificateBundle(t, pinnedBundle, pinnedServer.Certificate().Raw)
	alternateBundle := filepath.Join(bundleDir, "alternate.pem")
	writeCertificateBundle(t, alternateBundle, alternateServer.Certificate().Raw)
	t.Setenv("SSL_CERT_FILE", alternateBundle)
	t.Setenv("SSL_CERT_DIR", bundleDir)

	client, err := uploadHTTPClientForCABundle(pinnedBundle)
	if err != nil {
		t.Fatalf("uploadHTTPClientForCABundle() error = %v", err)
	}
	response, err := client.Get(pinnedServer.URL)
	if err != nil {
		t.Fatalf("pinned CA request failed with ambient override: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("pinned CA request status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
	if response, err := client.Get(alternateServer.URL); err == nil {
		response.Body.Close()
		t.Fatal("ambient CA override was trusted")
	}
}

func TestUploadHTTPClientIgnoresAmbientProxyOverrides(t *testing.T) {
	pinnedServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer pinnedServer.Close()

	proxyRequests := make(chan struct{}, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case proxyRequests <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	bundle := filepath.Join(t.TempDir(), "pinned.pem")
	writeCertificateBundle(t, bundle, pinnedServer.Certificate().Raw)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	client, err := uploadHTTPClientForCABundle(bundle)
	if err != nil {
		t.Fatalf("uploadHTTPClientForCABundle() error = %v", err)
	}
	response, err := client.Get(pinnedServer.URL)
	if err != nil {
		t.Fatalf("direct pinned request failed with ambient proxy: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("direct pinned request status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
	select {
	case <-proxyRequests:
		t.Fatal("ambient proxy received the pinned request")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestUploadHTTPClientFailsClosedForMissingOrInvalidCABundle(t *testing.T) {
	for name, content := range map[string][]byte{
		"missing": nil,
		"invalid": []byte("not a certificate"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ca-bundle.pem")
			if name == "invalid" {
				if err := os.WriteFile(path, content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := uploadHTTPClientForCABundle(path); err == nil {
				t.Fatal("uploadHTTPClientForCABundle() unexpectedly succeeded")
			}
		})
	}
}

func TestUploadRejectsRedirectAndDoesNotFollowIt(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	oldFactory := newUploadHTTPClient
	defer func() { artifactPath, readyPath, newUploadHTTPClient = oldPath, oldReady, oldFactory }()
	artifactPath, readyPath = path, ready
	var followed bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed = true
	}))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	newUploadHTTPClient = func() *http.Client { return redirect.Client() }
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", redirect.URL+"/redirect")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")

	if err := upload(context.Background()); !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("upload() error = %v, want redirect refusal", err)
	}
	if followed {
		t.Fatal("redirect target was contacted")
	}
}

func TestUploadRejectsNonPrivateOrSymlinkedFiles(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "private") {
		t.Fatalf("mode error = %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "link.archive")
	if err := os.Rename(path, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(link, path); err != nil {
		t.Fatal(err)
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "private") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestUploadRejectsNonPrivateOrSymlinkedReadyMarker(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	if err := os.Chmod(ready, 0640); err != nil {
		t.Fatal(err)
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "private") {
		t.Fatalf("mode error = %v", err)
	}
	if err := os.Chmod(ready, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(ready), "link.ready")
	if err := os.Rename(ready, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(link, ready); err != nil {
		t.Fatal(err)
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "private") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestOpenPrivateNoFollowFailureIsPathSafeAndNeutral(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "private-target")
	if err := os.WriteFile(target, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "untrusted-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err = openPrivateNoFollow(link, expected)
	if err == nil {
		t.Fatal("openPrivateNoFollow() unexpectedly followed a link")
	}
	message := err.Error()
	if strings.Contains(message, "archive") || strings.Contains(message, link) || strings.Contains(message, directory) {
		t.Fatalf("private open failure leaked or mislabeled a path: %q", message)
	}
}

func TestUploadRejectsForgedReadyMarker(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	if err := os.WriteFile(ready, []byte("ready\nforged\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "marker is invalid") {
		t.Fatalf("forged marker error = %v", err)
	}
}

func TestUploadRejectsEmptyTokenAndURLQuery(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object?replay=true")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	if err := upload(context.Background()); !strings.Contains(err.Error(), "URL") {
		t.Fatalf("query error = %v", err)
	}
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object?")
	if err := upload(context.Background()); !strings.Contains(err.Error(), "URL") {
		t.Fatalf("force-query error = %v", err)
	}
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "")
	if err := upload(context.Background()); !strings.Contains(err.Error(), "token") {
		t.Fatalf("empty token error = %v", err)
	}
}

func TestUploadRejectsInvalidOrNarrowedArchiveCap(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	for _, value := range []string{"", "0", "-1", "not-a-number", "536870913", "00000000000000000001"} {
		t.Setenv("BREAKGLASS_ARTIFACT_MAX_BYTES", value)
		if err := upload(context.Background()); !strings.Contains(err.Error(), "BREAKGLASS_ARTIFACT_MAX_BYTES") {
			t.Fatalf("max bytes %q error = %v", value, err)
		}
	}
	t.Setenv("BREAKGLASS_ARTIFACT_MAX_BYTES", "1")
	if err := upload(context.Background()); !strings.Contains(err.Error(), "bounded upload limit") {
		t.Fatalf("narrow cap error = %v", err)
	}
}

func TestConfiguredUploadTimeout(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  time.Duration
		err   bool
	}{
		{name: "default", want: uploadTimeout},
		{name: "bounded", value: "15s", want: 15 * time.Second},
		{name: "one hour", value: "1h", want: time.Hour},
		{name: "empty", value: "", err: true},
		{name: "zero", value: "0s", err: true},
		{name: "too long", value: "1h1s", err: true},
		{name: "not duration", value: "fifteen", err: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "default" {
				t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TIMEOUT", "")
				if err := os.Unsetenv("BREAKGLASS_ARTIFACT_UPLOAD_TIMEOUT"); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TIMEOUT", test.value)
			}
			got, err := configuredUploadTimeout()
			if test.err {
				if err == nil {
					t.Fatalf("configuredUploadTimeout() = %s, want error", got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("configuredUploadTimeout() = %s, %v, want %s", got, err, test.want)
			}
		})
	}
}

func TestUploadRejectsArchiveMutationDuringTransfer(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady, oldFactory := artifactPath, readyPath, newUploadHTTPClient
	defer func() { artifactPath, readyPath, newUploadHTTPClient = oldPath, oldReady, oldFactory }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	newUploadHTTPClient = func() *http.Client {
		return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if _, err := io.ReadAll(request.Body); err != nil {
				return nil, err
			}
			if err := os.Truncate(path, 0); err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})}
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "changed or was truncated") {
		t.Fatalf("mutation error = %v", err)
	}
}

func TestUploadRejectsSameSizeArchiveMutationDuringTransfer(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady, oldFactory := artifactPath, readyPath, newUploadHTTPClient
	defer func() { artifactPath, readyPath, newUploadHTTPClient = oldPath, oldReady, oldFactory }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	newUploadHTTPClient = func() *http.Client {
		return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if _, err := io.ReadAll(request.Body); err != nil {
				return nil, err
			}
			if err := os.WriteFile(path, []byte("changed-bytes"), 0600); err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})}
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "changed") {
		t.Fatalf("same-size mutation error = %v", err)
	}
}

func TestUploadEnforcesImmutableRecipeArchiveCeilings(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	manifest := filepath.Join(filepath.Dir(path), "artifact.manifest.json")

	if err := os.WriteFile(manifest, systemSummaryManifest(16777217), 0600); err != nil {
		t.Fatal(err)
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "immutable recipe ceiling") {
		t.Fatalf("summary manifest ceiling error = %v", err)
	}
	if err := os.WriteFile(manifest, []byte(strings.Replace(string(crashdumpManifest(maxArchiveBytes)), "crashdump-collection.v1", "unknown.v1", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("unknown recipe error = %v", err)
	}
}

func TestUploadRejectsManifestWithUnknownFields(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	manifest := filepath.Join(filepath.Dir(path), "artifact.manifest.json")
	valid := strings.TrimSuffix(string(systemSummaryManifest(16777216)), "}\n")
	if err := os.WriteFile(manifest, []byte(valid+`,"forged":"field"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "manifest is invalid") {
		t.Fatalf("unknown-field manifest error = %v", err)
	}
}

func TestRecipeArchiveLimitRejectsMissingWrongAndCrossRecipeIdentity(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "artifact.manifest.json")
	validSummary := string(systemSummaryManifest(16777216))
	validCrashdump := string(crashdumpManifest(maxArchiveBytes))
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "missing schema version", body: strings.Replace(validSummary, `"schema_version":"diagnostic-artifact/v1",`, "", 1)},
		{name: "wrong schema version", body: strings.Replace(validSummary, "diagnostic-artifact/v1", "diagnostic-artifact/v2", 1)},
		{name: "missing recipe version", body: strings.Replace(validSummary, `"recipe_version":1,`, "", 1)},
		{name: "wrong recipe version", body: strings.Replace(validSummary, `"recipe_version":1`, `"recipe_version":2`, 1)},
		{name: "wrong archive format", body: strings.Replace(validSummary, `"archive_format":"tar.gz"`, `"archive_format":"zip"`, 1)},
		{name: "summary with crashdump identity", body: strings.Replace(validSummary, `"node":null,"archive_format"`, `"node":"node-a","archive_format"`, 1)},
		{name: "crashdump with summary identity", body: strings.Replace(validCrashdump, `"node":"node-a","archive_format"`, `"node":null,"archive_format"`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(manifest, []byte(test.body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := recipeArchiveLimit(manifest); err == nil {
				t.Fatal("recipeArchiveLimit() unexpectedly accepted manifest")
			}
		})
	}
}

func TestRetryableUsesTypedFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "temporary response", err: &uploadResponseError{statusCode: http.StatusServiceUnavailable, temporary: true}, want: true},
		{name: "permanent authorization response", err: &uploadResponseError{statusCode: http.StatusUnauthorized}, want: false},
		{name: "redirect contract", err: errRedirect, want: false},
		{name: "caller cancellation", err: context.Canceled, want: false},
		{name: "caller deadline", err: context.DeadlineExceeded, want: false},
		{name: "timeout network error", err: &url.Error{Op: "Put", URL: "https://upload.example.invalid/object", Err: &net.DNSError{IsTimeout: true}}, want: true},
		{name: "TLS trust failure", err: &url.Error{Op: "Put", URL: "https://upload.example.invalid/object", Err: x509.UnknownAuthorityError{}}, want: false},
		{name: "lookalike text is not typed", err: errors.New("temporary upload response: 503; connection reset; i/o timeout"), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := retryable(test.err); got != test.want {
				t.Fatalf("retryable(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	client := &http.Client{Timeout: 20 * time.Millisecond}
	response, err := client.Get(server.URL)
	if response != nil {
		defer response.Body.Close()
	}
	if err == nil {
		t.Fatal("http.Client timeout unexpectedly succeeded")
	}
	if !retryable(err) {
		t.Fatalf("retryable(http.Client timeout %T: %v) = false, want true", err, err)
	}
}

func TestUploadRetriesOnlyTemporaryHTTPResponses(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    int
		wantCalls int
	}{
		{name: "temporary service unavailable", status: http.StatusServiceUnavailable, wantCalls: maxAttempts},
		{name: "permanent unauthorized", status: http.StatusUnauthorized, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, ready := uploadFixture(t, []byte("archive-bytes"))
			oldPath, oldReady, oldFactory := artifactPath, readyPath, newUploadHTTPClient
			defer func() { artifactPath, readyPath, newUploadHTTPClient = oldPath, oldReady, oldFactory }()
			artifactPath, readyPath = path, ready
			t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
			t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
			calls := 0
			newUploadHTTPClient = func() *http.Client {
				return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					calls++
					_, _ = io.Copy(io.Discard, request.Body)
					return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
				})}
			}
			if err := upload(context.Background()); err == nil {
				t.Fatal("upload() unexpectedly succeeded")
			}
			if calls != test.wantCalls {
				t.Fatalf("upload() made %d requests, want %d", calls, test.wantCalls)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestUploadRejectsMissingReadyAndOversizedArchive(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, filepath.Join(filepath.Dir(ready), "missing.ready")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	if err := upload(context.Background()); !strings.Contains(err.Error(), "artifact.ready") {
		t.Fatalf("missing ready error = %v", err)
	}

	artifactPath, readyPath = filepath.Join(filepath.Dir(path), "oversized.archive"), ready
	if err := os.WriteFile(artifactPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(artifactPath, maxArchiveBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "bounded upload limit") {
		t.Fatalf("oversized error = %v", err)
	}
}

func TestUploadRejectsHTTPUnlessExplicitDevelopmentOptIn(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "http://upload.example.invalid/object")
	if err := upload(context.Background()); !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("HTTP error = %v", err)
	}
}

func uploadFixture(t *testing.T, content []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	archive := filepath.Join(dir, "artifact.tar.gz")
	ready := filepath.Join(dir, "artifact.ready")
	if err := os.WriteFile(archive, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ready, []byte("ready\n"), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "artifact.manifest.json")
	if err := os.WriteFile(manifest, crashdumpManifest(maxArchiveBytes), 0600); err != nil {
		t.Fatal(err)
	}
	return archive, ready
}

func systemSummaryManifest(maxBytes int64) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":"diagnostic-artifact/v1","recipe":"system-summary.v1","recipe_version":1,"node":null,"archive_format":"tar.gz","inputs":{"maxArchiveBytes":%d,"detailLevel":"basic"},"payload_sha256":"0000000000000000000000000000000000000000000000000000000000000000","file_count":1,"bytes":1,"exit_code":0,"exit_semantics":"0=complete; non-zero=not published"}`+"\n", maxBytes))
}

func crashdumpManifest(maxBytes int64) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":"diagnostic-artifact/v1","recipe":"crashdump-collection.v1","recipe_version":1,"node":"node-a","archive_format":"tar.gz","inputs":{"maxAgeMinutes":1440,"node":"node-a","maxArchiveBytes":%d},"payload_sha256":"0000000000000000000000000000000000000000000000000000000000000000","file_count":0,"bytes":0,"exit_code":0,"exit_semantics":"0=complete; non-zero=not published"}`+"\n", maxBytes))
}

func writeCertificateBundle(t *testing.T, path string, certificateDER []byte) {
	t.Helper()
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	if err := os.WriteFile(path, certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
}

func newIndependentTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	return server
}
