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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
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

	if err := os.WriteFile(manifest, []byte(`{"recipe":"system-summary.v1","inputs":{"maxArchiveBytes":16777217}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "immutable recipe ceiling") {
		t.Fatalf("summary manifest ceiling error = %v", err)
	}
	if err := os.WriteFile(manifest, []byte(`{"recipe":"unknown.v1","inputs":{"maxArchiveBytes":1}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := upload(context.Background()); !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("unknown recipe error = %v", err)
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
	if err := os.WriteFile(manifest, []byte(`{"recipe":"crashdump-collection.v1","inputs":{"maxArchiveBytes":536870912}}`), 0600); err != nil {
		t.Fatal(err)
	}
	return archive, ready
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
