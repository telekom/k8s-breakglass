// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut || auth != "Bearer one-time-token" || body != string(expected) {
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

func TestUploadRejectsCorruptOrTamperedArchive(t *testing.T) {
	for _, test := range []struct {
		name string
		make func(t *testing.T, path string, sidecar []byte)
		want string
	}{
		{
			name: "corrupt gzip",
			make: func(t *testing.T, path string, _ []byte) {
				if err := os.WriteFile(path, []byte("not-a-gzip"), 0600); err != nil {
					t.Fatal(err)
				}
			},
			want: "valid gzip",
		},
		{
			name: "tampered payload",
			make: func(t *testing.T, path string, sidecar []byte) {
				if err := os.WriteFile(path, gzipBytes(t, tarBytes(t, []byte("changed-bytes"), sidecar)), 0600); err != nil {
					t.Fatal(err)
				}
			},
			want: "checksum",
		},
		{
			name: "forged embedded manifest",
			make: func(t *testing.T, path string, sidecar []byte) {
				forged := append([]byte(nil), sidecar...)
				forged = bytes.Replace(forged, []byte(`"exit_code":0`), []byte(`"exit_code":1`), 1)
				if err := os.WriteFile(path, gzipBytes(t, tarBytes(t, []byte("archive-bytes"), forged)), 0600); err != nil {
					t.Fatal(err)
				}
			},
			want: "differs from sidecar",
		},
		{
			name: "duplicate payload",
			make: func(t *testing.T, path string, sidecar []byte) {
				if err := os.WriteFile(path, gzipBytes(t, duplicateTarBytes(t, []byte("archive-bytes"), sidecar)), 0600); err != nil {
					t.Fatal(err)
				}
			},
			want: "duplicate",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, ready := uploadFixture(t, []byte("archive-bytes"))
			oldPath, oldReady := artifactPath, readyPath
			defer func() { artifactPath, readyPath = oldPath, oldReady }()
			artifactPath, readyPath = path, ready
			t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
			t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
			sidecar, err := os.ReadFile(filepath.Join(filepath.Dir(path), "artifact.manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			test.make(t, path, sidecar)
			if err := upload(context.Background()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("upload() error = %v, want %q", err, test.want)
			}
		})
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

func TestUploadURLRejectsWhitespace(t *testing.T) {
	for _, value := range []string{" https://upload.example.invalid/object", "https://upload.example.invalid/exact object", "https://upload.example.invalid/object\u00a0"} {
		t.Run(fmt.Sprintf("url-%q", value), func(t *testing.T) {
			t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", value)
			if _, err := uploadURL(); err == nil {
				t.Fatal("uploadURL() accepted whitespace")
			}
		})
	}
}

func TestUploadTokenRejectsEmbeddedWhitespace(t *testing.T) {
	for _, token := range []string{"one two", "one\ttwo", "one\u00a0two"} {
		t.Run(fmt.Sprintf("token-%q", token), func(t *testing.T) {
			t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", token)
			if _, err := uploadToken(); err == nil {
				t.Fatal("uploadToken() accepted embedded whitespace")
			}
		})
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
	if err := upload(context.Background()); !strings.Contains(err.Error(), "changed") {
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

func TestManifestRejectsDuplicateJSONKeys(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "artifact.manifest.json")
	valid := string(systemSummaryManifest(16777216))
	for name, body := range map[string]string{
		"top-level": strings.Replace(valid, `"recipe":"system-summary.v1",`, `"recipe":"system-summary.v1","recipe":"crashdump-collection.v1",`, 1),
		"nested":    strings.Replace(valid, `"detailLevel":"basic"`, `"detailLevel":"basic","detailLevel":"extended"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(manifestPath, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := recipeArchiveLimit(manifestPath); err == nil || !strings.Contains(err.Error(), "manifest is invalid") {
				t.Fatalf("recipeArchiveLimit() error = %v, want duplicate-key rejection", err)
			}
		})
	}
}

func TestManifestRejectsUnboundOrForgedAuthorizationFields(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "artifact.manifest.json")
	valid := string(systemSummaryManifest(16777216))
	for name, body := range map[string]string{
		"artifact ID":       strings.Replace(valid, "dsa-0123456789abcdef01234567", "dsa-0123456789abcdef0123456!", 1),
		"session namespace": strings.Replace(valid, `"namespace":"breakglass-test"`, `"namespace":"../other"`, 1),
		"session UID":       strings.Replace(valid, `"uid":"uid-0123456789abcdef"`, `"uid":""`, 1),
		"redaction profile": strings.Replace(valid, `"profile":"credential-text.v1"`, `"profile":"raw secrets"`, 1),
		"redaction version": strings.Replace(valid, `"version":1`, `"version":0`, 1),
		"unknown output":    strings.Replace(valid, `"files/system-summary.json","manifest.json","stderr.log","stdout.log"`, `"files/other.json","manifest.json","stderr.log","stdout.log"`, 1),
		"duplicate output":  strings.Replace(valid, `"files/system-summary.json","manifest.json","stderr.log","stdout.log"`, `"files/system-summary.json","files/system-summary.json","stderr.log","stdout.log"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(manifestPath, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := recipeArchiveLimit(manifestPath); err == nil {
				t.Fatal("recipeArchiveLimit() unexpectedly accepted forged authorization fields")
			}
		})
	}
}

func TestUploadRejectsManifestEnvironmentMismatch(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	for name, value := range map[string]string{
		"artifact":    "dsa-abcdefabcdefabcdefabcdef",
		"session uid": "uid-replayed",
		"redaction":   "unredacted.v1",
	} {
		t.Run(name, func(t *testing.T) {
			switch name {
			case "artifact":
				t.Setenv("BREAKGLASS_ARTIFACT_ID", value)
			case "session uid":
				t.Setenv("BREAKGLASS_ARTIFACT_SESSION_UID", value)
			case "redaction":
				t.Setenv("BREAKGLASS_ARTIFACT_REDACTION_PROFILE", value)
			}
			if err := upload(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Fatalf("upload() error = %v, want manifest/environment binding failure", err)
			}
		})
	}
}

func TestEmbeddedManifestRejectsDuplicateJSONKeys(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, ready
	sidecar, err := os.ReadFile(filepath.Join(filepath.Dir(path), "artifact.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(sidecar, []byte(`"recipe":"crashdump-collection.v1",`), []byte(`"recipe":"crashdump-collection.v1","recipe":"crashdump-collection.v1",`), 1)
	archive := gzipBytes(t, tarBytes(t, []byte("archive-bytes"), duplicate))
	if err := os.WriteFile(path, archive, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "artifact.manifest.json"), sidecar, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	if err := upload(context.Background()); err == nil || !strings.Contains(err.Error(), "embedded manifest is invalid") {
		t.Fatalf("upload() error = %v, want embedded duplicate-key rejection", err)
	}
}

func TestTarExtensionParsingIsNarrowAndBounded(t *testing.T) {
	validLongName := append([]byte("files/coredumps/long-name.dump"), 0)
	validLongName = append(validLongName, make([]byte, 8)...)
	validPAX := paxRecord("path", "files/coredumps/pax-name.dump")
	for _, test := range []struct {
		name     string
		typeflag byte
		content  []byte
		want     string
		valid    bool
	}{
		{name: "valid GNU long name", typeflag: 'L', content: validLongName, want: "files/coredumps/long-name.dump", valid: true},
		{name: "zero GNU long name", typeflag: 'L', content: []byte{0}, valid: false},
		{name: "missing GNU terminator", typeflag: 'L', content: []byte("name"), valid: false},
		{name: "nonzero GNU padding", typeflag: 'L', content: []byte{'n', 0, 1}, valid: false},
		{name: "valid PAX path", typeflag: 'x', content: validPAX, want: "files/coredumps/pax-name.dump", valid: true},
		{name: "zero PAX record", typeflag: 'x', content: nil, valid: false},
		{name: "malformed PAX length", typeflag: 'x', content: []byte("5 path=x\n"), valid: false},
		{name: "PAX size is unsupported", typeflag: 'x', content: paxRecord("size", "1"), valid: false},
		{name: "PAX mtime is unsupported", typeflag: 'x', content: paxRecord("mtime", "1"), valid: false},
		{name: "GNU sparse is unsupported", typeflag: 'x', content: paxRecord("GNU.sparse.map", "0,1"), valid: false},
		{name: "GNU long link is unsupported", typeflag: 'K', content: validLongName, valid: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseTarExtension(test.typeflag, test.content)
			if test.valid {
				if err != nil || got != test.want {
					t.Fatalf("parseTarExtension() = %q, %v, want %q", got, err, test.want)
				}
			} else if err == nil {
				t.Fatalf("parseTarExtension() unexpectedly accepted %q", got)
			}
		})
	}
}

func TestTarHeaderRejectsBadMagicAndStringPadding(t *testing.T) {
	valid := rawTarHeader("files", tar.TypeDir, 0)
	if _, err := parseTarHeader(valid); err != nil {
		t.Fatalf("valid tar header rejected: %v", err)
	}
	busybox := append([]byte(nil), valid...)
	copy(busybox[257:265], []byte("ustar  \x00"))
	setTarChecksum(busybox)
	if _, err := parseTarHeader(busybox); err != nil {
		t.Fatalf("BusyBox tar header rejected: %v", err)
	}
	for name, mutate := range map[string]func([]byte){
		"magic":          func(header []byte) { header[257] = 'x' },
		"name padding":   func(header []byte) { header[5] = 0; header[6] = 'x' },
		"prefix padding": func(header []byte) { header[345] = 0; header[346] = 'x' },
	} {
		t.Run(name, func(t *testing.T) {
			header := append([]byte(nil), valid...)
			mutate(header)
			setTarChecksum(header)
			if _, err := parseTarHeader(header); err == nil {
				t.Fatal("parseTarHeader() unexpectedly accepted malformed header")
			}
		})
	}
}

func TestArchiveRejectsCompressedExtensionMetadataAccumulation(t *testing.T) {
	const extensionSize = 600000
	content := make([]byte, extensionSize)
	content[0] = 'x'
	content[1] = 0
	var raw bytes.Buffer
	for index := 0; index < 2; index++ {
		header := rawTarHeader("././@LongLink", 'L', extensionSize)
		raw.Write(header)
		raw.Write(content)
		raw.Write(make([]byte, int(paddedTarSizeForTest(extensionSize))-extensionSize))
	}
	compressed := gzipBytes(t, raw.Bytes())
	if len(compressed) > 10000 {
		t.Fatalf("compressed extension fixture is not a bounded bomb: %d bytes", len(compressed))
	}
	archivePath := filepath.Join(t.TempDir(), "artifact.tar.gz")
	if err := os.WriteFile(archivePath, compressed, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyArchiveContract(context.Background(), file, info.Size(), artifactManifest{}, nil); err == nil || !strings.Contains(err.Error(), "extension metadata") {
		t.Fatalf("verifyArchiveContract() error = %v, want aggregate extension bound", err)
	}
}

func TestUploadStopsBeforePreflightWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := upload(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("upload() error = %v, want context canceled", err)
	}
}

func TestContextLimitedReaderDoesNotEnterBlockingPreflightRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := make(chan struct{}, 1)
	reader := &contextLimitedReader{ctx: ctx, reader: blockingReader{started: started}, remaining: 1}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("contextLimitedReader.Read() error = %v, want context canceled", err)
	}
	select {
	case <-started:
		t.Fatal("blocking preflight source was read after cancellation")
	default:
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
		{name: "non-hex payload checksum", body: strings.Replace(validSummary, strings.Repeat("0", sha256.Size*2), strings.Repeat("g", sha256.Size*2), 1)},
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

func TestUploadRetriesPerAttemptTimeoutOnlyWithinTotalBudget(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady, oldFactory := artifactPath, readyPath, newUploadHTTPClient
	defer func() { artifactPath, readyPath, newUploadHTTPClient = oldPath, oldReady, oldFactory }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TIMEOUT", "2s")
	calls := 0
	newUploadHTTPClient = func() *http.Client {
		return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if calls < maxAttempts {
				return nil, &url.Error{Op: "PUT", URL: request.URL.String(), Err: perAttemptTimeoutError{}}
			}
			_, _ = io.Copy(io.Discard, request.Body)
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})}
	}
	if err := upload(context.Background()); err != nil {
		t.Fatalf("upload() error = %v", err)
	}
	if calls != maxAttempts {
		t.Fatalf("upload() made %d requests, want %d attempts while total budget remained", calls, maxAttempts)
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
		{name: "expired authorization", status: http.StatusGone, wantCalls: 1},
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

func TestUploadTimeoutBoundsRetryBudget(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady, oldFactory := artifactPath, readyPath, newUploadHTTPClient
	defer func() { artifactPath, readyPath, newUploadHTTPClient = oldPath, oldReady, oldFactory }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "https://upload.example.invalid/object")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN", "one-time-token")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_TIMEOUT", "100ms")
	calls := 0
	newUploadHTTPClient = func() *http.Client {
		return &http.Client{Timeout: time.Hour, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			_, _ = io.Copy(io.Discard, request.Body)
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})}
	}
	started := time.Now()
	err := upload(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("upload() error = %v, want deadline exceeded", err)
	}
	if calls > 1 {
		t.Fatalf("upload() made %d requests after total timeout, want at most 1", calls)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("upload() exceeded total timeout budget: %s", elapsed)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type perAttemptTimeoutError struct{}

func (perAttemptTimeoutError) Error() string   { return "per-attempt timeout" }
func (perAttemptTimeoutError) Timeout() bool   { return true }
func (perAttemptTimeoutError) Temporary() bool { return true }

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

func TestUploadRejectsHTTPWithoutDowngrade(t *testing.T) {
	path, ready := uploadFixture(t, []byte("archive-bytes"))
	oldPath, oldReady := artifactPath, readyPath
	defer func() { artifactPath, readyPath = oldPath, oldReady }()
	artifactPath, readyPath = path, ready
	t.Setenv("BREAKGLASS_ARTIFACT_ALLOW_INSECURE_HTTP", "true")
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_URL", "http://upload.example.invalid/object")
	if err := upload(context.Background()); !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("HTTP error = %v", err)
	}
}

func uploadFixture(t *testing.T, content []byte) (string, string) {
	t.Helper()
	t.Setenv("BREAKGLASS_ARTIFACT_ID", "dsa-0123456789abcdef01234567")
	t.Setenv("BREAKGLASS_ARTIFACT_SESSION_NAMESPACE", "breakglass-test")
	t.Setenv("BREAKGLASS_ARTIFACT_SESSION_NAME", "diagnostic-smoke")
	t.Setenv("BREAKGLASS_ARTIFACT_SESSION_UID", "uid-0123456789abcdef")
	t.Setenv("BREAKGLASS_ARTIFACT_REDACTION_PROFILE", "credential-text.v1")
	t.Setenv("BREAKGLASS_ARTIFACT_REDACTION_VERSION", "1")
	dir := t.TempDir()
	archive := filepath.Join(dir, "artifact.tar.gz")
	ready := filepath.Join(dir, "artifact.ready")
	payload := tarBytes(t, content, nil)
	payloadHash := sha256.Sum256(payload)
	manifestBytes := validCrashdumpManifest(maxArchiveBytes, hex.EncodeToString(payloadHash[:]), 1, int64(len(content)))
	archiveBytes := tarBytes(t, content, manifestBytes)
	var compressed strings.Builder
	zipWriter := gzip.NewWriter(&compressed)
	if _, err := zipWriter.Write(archiveBytes); err != nil {
		t.Fatal(err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, []byte(compressed.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ready, []byte("ready\n"), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "artifact.manifest.json")
	if err := os.WriteFile(manifest, manifestBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return archive, ready
}

func gzipBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var compressed strings.Builder
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return []byte(compressed.String())
}

func duplicateTarBytes(t *testing.T, content, manifest []byte) []byte {
	t.Helper()
	var output strings.Builder
	writer := tar.NewWriter(&output)
	write := func(header *tar.Header, body []byte) {
		t.Helper()
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(body) > 0 {
			if _, err := writer.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(&tar.Header{Name: "files", Mode: 0755, Typeflag: tar.TypeDir}, nil)
	write(&tar.Header{Name: "files/coredumps", Mode: 0755, Typeflag: tar.TypeDir}, nil)
	for i := 0; i < 2; i++ {
		write(&tar.Header{Name: "files/coredumps/artifact.dump", Mode: 0600, Size: int64(len(content))}, content)
	}
	write(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifest))}, manifest)
	write(&tar.Header{Name: "stderr.log", Mode: 0600}, nil)
	write(&tar.Header{Name: "stdout.log", Mode: 0600}, nil)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return []byte(output.String())
}

func tarBytes(t *testing.T, content, manifest []byte) []byte {
	t.Helper()
	var output strings.Builder
	writer := tar.NewWriter(&output)
	writeHeader := func(name string, mode int64, size int64, typeflag byte) {
		t.Helper()
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: size, Typeflag: typeflag}); err != nil {
			t.Fatal(err)
		}
	}
	writeHeader("files", 0755, 0, tar.TypeDir)
	writeHeader("files/coredumps", 0755, 0, tar.TypeDir)
	writeHeader("files/coredumps/artifact.dump", 0600, int64(len(content)), tar.TypeReg)
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if manifest != nil {
		writeHeader("manifest.json", 0600, int64(len(manifest)), tar.TypeReg)
		if _, err := writer.Write(manifest); err != nil {
			t.Fatal(err)
		}
	}
	writeHeader("stderr.log", 0600, 0, tar.TypeReg)
	writeHeader("stdout.log", 0600, 0, tar.TypeReg)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return []byte(output.String())
}

func systemSummaryManifest(maxBytes int64) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":"diagnostic-artifact/v1","recipe":"system-summary.v1","recipe_version":1,"artifact_id":"dsa-0123456789abcdef01234567","session":{"namespace":"breakglass-test","name":"diagnostic-smoke","uid":"uid-0123456789abcdef"},"redaction":{"profile":"credential-text.v1","version":1},"node":null,"archive_format":"tar.gz","inputs":{"maxArchiveBytes":%d,"detailLevel":"basic"},"declared_outputs":["files/system-summary.json","manifest.json","stderr.log","stdout.log"],"payload_sha256":"0000000000000000000000000000000000000000000000000000000000000000","file_count":1,"bytes":1,"exit_code":0,"exit_semantics":"0=complete; non-zero=not published"}`+"\n", maxBytes))
}

func crashdumpManifest(maxBytes int64) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":"diagnostic-artifact/v1","recipe":"crashdump-collection.v1","recipe_version":1,"artifact_id":"dsa-0123456789abcdef01234567","session":{"namespace":"breakglass-test","name":"diagnostic-smoke","uid":"uid-0123456789abcdef"},"redaction":{"profile":"credential-text.v1","version":1},"node":"node-a","archive_format":"tar.gz","inputs":{"maxAgeMinutes":1440,"node":"node-a","maxArchiveBytes":%d},"declared_outputs":["files/coredumps/","manifest.json","stderr.log","stdout.log"],"payload_sha256":"0000000000000000000000000000000000000000000000000000000000000000","file_count":0,"bytes":0,"exit_code":0,"exit_semantics":"0=complete; non-zero=not published"}`+"\n", maxBytes))
}

func validCrashdumpManifest(maxBytes int64, payloadSHA string, fileCount, bytes int64) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":"diagnostic-artifact/v1","recipe":"crashdump-collection.v1","recipe_version":1,"artifact_id":"dsa-0123456789abcdef01234567","session":{"namespace":"breakglass-test","name":"diagnostic-smoke","uid":"uid-0123456789abcdef"},"redaction":{"profile":"credential-text.v1","version":1},"node":"node-a","archive_format":"tar.gz","inputs":{"maxAgeMinutes":1440,"node":"node-a","maxArchiveBytes":%d},"declared_outputs":["files/coredumps/","manifest.json","stderr.log","stdout.log"],"payload_sha256":"%s","file_count":%d,"bytes":%d,"exit_code":0,"exit_semantics":"0=complete; non-zero=not published"}`+"\n", maxBytes, payloadSHA, fileCount, bytes))
}

func paxRecord(key, value string) []byte {
	for length := len(key) + len(value) + 3; ; length++ {
		record := fmt.Sprintf("%d %s=%s\n", length, key, value)
		if len(record) == length {
			return []byte(record)
		}
	}
}

func rawTarHeader(name string, typeflag byte, size int64) []byte {
	header := make([]byte, int(tarBlockSize))
	copy(header[0:100], name)
	copy(header[100:108], "0000644\x00")
	copy(header[108:116], "0000000\x00")
	copy(header[116:124], "0000000\x00")
	copy(header[124:136], fmt.Sprintf("%011o\x00", size))
	copy(header[136:148], "00000000000\x00")
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	copy(header[156:157], []byte{typeflag})
	copy(header[257:265], []byte("ustar\x0000"))
	setTarChecksum(header)
	return header
}

func setTarChecksum(header []byte) {
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	var sum int64
	for _, value := range header {
		sum += int64(value)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

func paddedTarSizeForTest(size int64) int64 {
	return ((size + tarBlockSize - 1) / tarBlockSize) * tarBlockSize
}

type blockingReader struct {
	started chan<- struct{}
}

func (reader blockingReader) Read([]byte) (int, error) {
	reader.started <- struct{}{}
	return 0, io.ErrNoProgress
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
