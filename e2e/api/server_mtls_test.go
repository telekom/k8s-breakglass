/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

const mtlsMountPath = "/etc/breakglass-mtls"

// mtlsVariant is one extra breakglass server deployed next to the main
// controller with its own server.clientAuth setting.
type mtlsVariant struct {
	name       string
	clientAuth string // "" leaves server.clientAuth unset (the default)
	withCA     bool   // set server.clientCAFile
	httpOff    bool   // --enable-frontend=false --enable-api=false
}

// TestServerMTLS deploys API/frontend replicas of the real breakglass image
// (Pattern 2 in docs/scaling-and-leader-election.md) with HTTPS and each
// server.clientAuth mode, then drives TLS handshakes and API calls through a
// port-forward. The main controller keeps plain HTTP, so it covers the "off"
// path for every other e2e test.
func TestServerMTLS(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx

	serverCA := newMTLSCA(t, "e2e-mtls-server-ca")
	trustedCA := newMTLSCA(t, "e2e-mtls-trusted-client-ca")
	otherCA := newMTLSCA(t, "e2e-mtls-untrusted-client-ca")
	serverCert := serverCA.issue(t, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))
	trusted := trustedCA.issue(t, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))
	expired := trustedCA.issue(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute))
	untrusted := otherCA.issue(t, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))

	suffix := helpers.GenerateUniqueName("")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-mtls" + suffix, Namespace: s.Namespace, Labels: helpers.E2ELabelsWithFeature("server-mtls")},
		Data: map[string][]byte{
			"tls.crt":   serverCert.certPEM,
			"tls.key":   serverCert.keyPEM,
			"client-ca": trustedCA.certPEM,
		},
	}
	s.MustCreateResource(secret)

	variants := []mtlsVariant{
		{name: "default"},
		{name: "none", clientAuth: "none"},
		{name: "request", clientAuth: "request"},
		{name: "verifyifgiven", clientAuth: "verifyIfGiven", withCA: true},
		{name: "require", clientAuth: "require", withCA: true},
		{name: "invalid", clientAuth: "require"},
		{name: "invalid-nohttp", clientAuth: "require", httpOff: true},
	}
	deployments := map[string]string{}
	for _, v := range variants {
		deployments[v.name] = "e2e-mtls-" + v.name + suffix
		httpOn := fmt.Sprint(!v.httpOff)
		helpers.DeployServerReplica(t, s, helpers.ServerReplica{
			Name: deployments[v.name],
			EditConfig: func(cfg map[string]any) {
				server, _ := cfg["server"].(map[string]any)
				if server == nil {
					server = map[string]any{}
				}
				server["tlsCertFile"] = mtlsMountPath + "/tls.crt"
				server["tlsKeyFile"] = mtlsMountPath + "/tls.key"
				if v.clientAuth != "" {
					server["clientAuth"] = v.clientAuth
				}
				if v.withCA {
					server["clientCAFile"] = mtlsMountPath + "/client-ca"
				}
				cfg["server"] = server
			},
			Flags: map[string]string{"enable-frontend": httpOn, "enable-api": httpOn},
			Volumes: []corev1.Volume{{
				Name:         "e2e-mtls",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret.Name}},
			}},
			VolumeMounts: []corev1.VolumeMount{{Name: "e2e-mtls", MountPath: mtlsMountPath, ReadOnly: true}},
		})
	}
	for _, v := range variants {
		if v.name == "invalid" {
			continue // never becomes ready; asserted below
		}
		require.NoError(t, helpers.WaitForDeploymentReady(ctx, s.Client, s.Namespace, deployments[v.name], 5*time.Minute),
			"variant %s did not become ready", v.name)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(serverCA.cert)
	token := s.TC.GetRequesterToken()

	type handshake struct {
		cert    *tls.Certificate
		wantErr string // TLS alert the client sees; empty means accepted
	}
	cases := map[string]map[string]handshake{
		"default": {"no-cert": {}, "trusted": {cert: &trusted.tls}, "untrusted": {cert: &untrusted.tls}},
		"none":    {"no-cert": {}, "trusted": {cert: &trusted.tls}, "untrusted": {cert: &untrusted.tls}},
		"request": {"no-cert": {}, "trusted": {cert: &trusted.tls}, "untrusted": {cert: &untrusted.tls}},
		"verifyifgiven": {
			"no-cert":   {},
			"trusted":   {cert: &trusted.tls},
			"untrusted": {cert: &untrusted.tls, wantErr: "tls: unknown certificate authority"},
			"expired":   {cert: &expired.tls, wantErr: "tls: expired certificate"},
		},
		"require": {
			"no-cert":   {wantErr: "tls: certificate required"},
			"trusted":   {cert: &trusted.tls},
			"untrusted": {cert: &untrusted.tls, wantErr: "tls: unknown certificate authority"},
			"expired":   {cert: &expired.tls, wantErr: "tls: expired certificate"},
		},
	}

	for _, mode := range []string{"default", "none", "request", "verifyifgiven", "require"} {
		t.Run(mode, func(t *testing.T) {
			// kubectl port-forward exits when the server resets a rejected
			// handshake, so every handshake gets its own forward.
			forward := func(t *testing.T) string {
				port, stop := helpers.StartPortForward(t, ctx, s.Namespace, deployments[mode], 8080, 0)
				t.Cleanup(stop)
				return fmt.Sprintf("https://localhost:%d", port)
			}

			for name, hs := range cases[mode] {
				t.Run(name, func(t *testing.T) {
					status, _, err := mtlsDo(ctx, mtlsClient(rootCAs, hs.cert), http.MethodGet, forward(t)+"/api/config", "", nil)
					if hs.wantErr != "" {
						require.Error(t, err, "handshake must be rejected")
						assert.ErrorContains(t, err, hs.wantErr)
						return
					}
					require.NoError(t, err)
					assert.Equal(t, http.StatusOK, status)
				})
			}

			// Once the handshake is accepted, the server behaves as before:
			// frontend, OIDC-authenticated API and the SAR webhook.
			c := mtlsClient(rootCAs, &trusted.tls)
			baseURL := forward(t)
			t.Run("frontend", func(t *testing.T) {
				status, body, err := mtlsDo(ctx, c, http.MethodGet, baseURL+"/", "", nil)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, status)
				assert.Contains(t, strings.ToLower(string(body)), "<html")
			})
			t.Run("api-oidc", func(t *testing.T) {
				status, _, err := mtlsDo(ctx, c, http.MethodGet, baseURL+"/api/breakglassSessions", token, nil)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, status)
			})
			t.Run("api-cert-grants-no-identity", func(t *testing.T) {
				status, _, err := mtlsDo(ctx, c, http.MethodGet, baseURL+"/api/breakglassSessions", "", nil)
				require.NoError(t, err)
				assert.Equal(t, http.StatusUnauthorized, status)
			})
			t.Run("sar-webhook", func(t *testing.T) {
				sar := authorizationv1.SubjectAccessReview{
					TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
					Spec: authorizationv1.SubjectAccessReviewSpec{
						User:               helpers.GetTestUserEmail(),
						ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "get", Resource: "pods", Namespace: "default"},
					},
				}
				body, err := json.Marshal(sar)
				require.NoError(t, err)
				status, resp, err := mtlsDo(ctx, c, http.MethodPost, baseURL+"/api/breakglass/webhook/authorize/"+s.Cluster, "", body)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, status, "webhook response: %s", resp)
				var got authorizationv1.SubjectAccessReview
				require.NoError(t, json.Unmarshal(resp, &got))
				assert.False(t, got.Status.Allowed, "a user without a session must not be allowed")
			})
		})
	}

	t.Run("off", func(t *testing.T) {
		// The main controller runs without server TLS: plain HTTP is unchanged.
		status, body, err := mtlsDo(ctx, helpers.DefaultHTTPClient(), http.MethodGet, helpers.GetAPIBaseURL()+"/", "", nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, strings.ToLower(string(body)), "<html")
		status, _, err = mtlsDo(ctx, helpers.DefaultHTTPClient(), http.MethodGet, helpers.GetAPIBaseURL()+"/api/breakglassSessions", token, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
	})

	t.Run("invalid-config-refuses-start", func(t *testing.T) {
		want := `fatal: validate server TLS config: server.clientAuth "require" needs server.clientCAFile`
		require.Eventually(t, func() bool {
			return helpers.ServerReplicaLogsContain(t, ctx, s.Namespace, deployments["invalid"], want)
		}, 3*time.Minute, 2*time.Second, "server with frontend/API must refuse an invalid client TLS config")
		var d appsv1.Deployment
		require.NoError(t, s.Client.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: deployments["invalid"]}, &d))
		assert.Zero(t, d.Status.AvailableReplicas)
	})

	t.Run("invalid-config-ignored-without-http-listener", func(t *testing.T) {
		// Waited for Ready above; prove the pod is still serving health checks
		// and has not restarted.
		var pods corev1.PodList
		require.NoError(t, s.Client.List(ctx, &pods, client.InNamespace(s.Namespace),
			client.MatchingLabels{helpers.ServerReplicaLabel: deployments["invalid-nohttp"]}))
		require.NotEmpty(t, pods.Items)
		for _, p := range pods.Items {
			for _, cs := range p.Status.ContainerStatuses {
				assert.True(t, cs.Ready, "container %s ready", cs.Name)
				assert.Zero(t, cs.RestartCount, "container %s restarted", cs.Name)
			}
		}
	})
}

// mtlsClient returns a client that trusts the test server CA and always
// presents cert (if any). With tls.Config.Certificates, crypto/tls silently
// omits a certificate whose issuer the server does not list, which would not
// exercise server-side verification.
func mtlsClient(rootCAs *x509.CertPool, cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs, ServerName: "localhost"}
	if cert != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
}

func mtlsDo(ctx context.Context, c *http.Client, method, url, token string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

type mtlsCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

type mtlsLeaf struct {
	tls     tls.Certificate
	certPEM []byte
	keyPEM  []byte
}

func newMTLSCA(t *testing.T, name string) mtlsCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return mtlsCA{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca mtlsCA) issue(t *testing.T, usage x509.ExtKeyUsage, notAfter time.Time) mtlsLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "e2e-mtls"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return mtlsLeaf{
		tls:     tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}
