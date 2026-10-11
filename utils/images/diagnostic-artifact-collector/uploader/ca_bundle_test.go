// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUploadCABundleAppendsTrustAndPreservesVerification(t *testing.T) {
	pinned := newIndependentTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) }))
	defer pinned.Close()
	private := newIndependentTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) }))
	defer private.Close()
	dir := t.TempDir()
	systemPath, privatePath := filepath.Join(dir, "system.pem"), filepath.Join(dir, "private.pem")
	writeCertificateBundle(t, systemPath, pinned.Certificate().Raw)
	writeCertificateBundle(t, privatePath, private.Certificate().Raw)
	for _, extra := range []string{"", privatePath} {
		client, err := uploadHTTPClientForCABundles(systemPath, extra)
		if err != nil {
			t.Fatal(err)
		}
		client.Timeout = 5 * time.Second
		defer client.CloseIdleConnections()
		for _, server := range []*httptest.Server{pinned, private} {
			request, err := http.NewRequestWithContext(context.Background(), http.MethodPut, server.URL+"/upload", strings.NewReader("artifact"))
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if extra == "" && server == private {
				var verification *tls.CertificateVerificationError
				if !errors.As(err, &verification) {
					t.Fatalf("without bundle, want certificate verification error, got %v", err)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("status = %d", response.StatusCode)
			}
		}
		client.CloseIdleConnections()
		client.Transport.(*http.Transport).TLSClientConfig.ServerName = "wrong.example"
		if response, err := client.Get(private.URL); err == nil {
			response.Body.Close()
			t.Fatal("additional bundle disabled hostname verification")
		}
	}
}

func TestUploadCABundleRejectsMissingMalformedAndOversizedBundles(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	dir := t.TempDir()
	systemPath := filepath.Join(dir, "system.pem")
	writeCertificateBundle(t, systemPath, server.Certificate().Raw)
	valid, err := os.ReadFile(systemPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"", "not a certificate", strings.Repeat("x", int(maxUploadCABundleBytes)+1),
		string(valid) + "trailing garbage",
		string(valid) + "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
		"leading garbage\n" + string(valid),
		string(valid) + "-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----\n"} {
		path := filepath.Join(dir, "extra.pem")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := uploadHTTPClientForCABundles(systemPath, path); err == nil {
			t.Fatal("invalid extra bundle accepted")
		}
	}
	if _, err := uploadHTTPClientForCABundles(systemPath, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing extra bundle accepted")
	}
	t.Setenv("BREAKGLASS_ARTIFACT_UPLOAD_CA_BUNDLE", "/arbitrary/path")
	if defaultUploadHTTPClient() != nil {
		t.Fatal("arbitrary bundle path accepted")
	}
}
