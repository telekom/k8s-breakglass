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
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

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

	base := mainControllerDeployment(t, ctx, s.Client, s.Namespace)
	baseConfig := controllerConfig(t, ctx, s.Client, s.Namespace, base)

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
		deployments[v.name] = deployMTLSVariant(t, s, base, baseConfig, secret.Name, suffix, v)
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
			port, stop := helpers.StartPortForward(t, ctx, s.Namespace, deployments[mode], 8080, 0)
			defer stop()
			baseURL := fmt.Sprintf("https://localhost:%d", port)

			for name, hs := range cases[mode] {
				t.Run(name, func(t *testing.T) {
					status, _, err := mtlsDo(ctx, mtlsClient(rootCAs, hs.cert), http.MethodGet, baseURL+"/api/config", "", nil)
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
		kube, err := kubernetes.NewForConfig(helpers.GetConfig(t))
		require.NoError(t, err)
		want := `fatal: validate server TLS config: server.clientAuth "require" needs server.clientCAFile`
		require.Eventually(t, func() bool {
			return podLogsContain(ctx, kube, s.Namespace, "e2e-mtls-variant=invalid"+suffix, want)
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
			client.MatchingLabels{"e2e-mtls-variant": "invalid-nohttp" + suffix}))
		require.NotEmpty(t, pods.Items)
		for _, p := range pods.Items {
			for _, cs := range p.Status.ContainerStatuses {
				assert.True(t, cs.Ready, "container %s ready", cs.Name)
				assert.Zero(t, cs.RestartCount, "container %s restarted", cs.Name)
			}
		}
	})
}

// mainControllerDeployment returns the deployment that runs the breakglass
// controller under test.
func mainControllerDeployment(t *testing.T, ctx context.Context, cli client.Client, ns string) *appsv1.Deployment {
	t.Helper()
	var list appsv1.DeploymentList
	require.NoError(t, cli.List(ctx, &list, client.InNamespace(ns), client.MatchingLabels{"app": "breakglass"}))
	require.Len(t, list.Items, 1, "expected exactly one breakglass controller deployment")
	return &list.Items[0]
}

// controllerConfig returns the controller's parsed config.yaml.
func controllerConfig(t *testing.T, ctx context.Context, cli client.Client, ns string, d *appsv1.Deployment) map[string]any {
	t.Helper()
	cm := configVolume(t, d).ConfigMap
	var obj corev1.ConfigMap
	require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: ns, Name: cm.Name}, &obj))
	var cfg map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(obj.Data[path.Base(configPath(t, d))]), &cfg))
	return cfg
}

func configPath(t *testing.T, d *appsv1.Deployment) string {
	t.Helper()
	for _, a := range d.Spec.Template.Spec.Containers[0].Args {
		if v, ok := strings.CutPrefix(a, "--config-path="); ok {
			return v
		}
	}
	t.Fatal("controller has no --config-path argument")
	return ""
}

func configVolume(t *testing.T, d *appsv1.Deployment) *corev1.Volume {
	t.Helper()
	dir := path.Dir(configPath(t, d))
	spec := &d.Spec.Template.Spec
	for _, m := range spec.Containers[0].VolumeMounts {
		if path.Clean(m.MountPath) != dir {
			continue
		}
		for i := range spec.Volumes {
			if spec.Volumes[i].Name == m.Name && spec.Volumes[i].ConfigMap != nil {
				return &spec.Volumes[i]
			}
		}
	}
	t.Fatalf("no ConfigMap volume mounted at %s", dir)
	return nil
}

// deployMTLSVariant creates a ConfigMap, Deployment and Service for one
// variant and returns their shared name. Pod labels are replaced so the main
// breakglass Service never routes to these pods.
func deployMTLSVariant(t *testing.T, s *helpers.TestSetup, base *appsv1.Deployment, baseConfig map[string]any,
	secretName, suffix string, v mtlsVariant,
) string {
	t.Helper()
	name := "e2e-mtls-" + v.name + suffix
	labels := helpers.E2ELabelsWithExtra(map[string]string{"e2e-mtls-variant": v.name + suffix})

	cfg := map[string]any{}
	for k, val := range baseConfig {
		cfg[k] = val
	}
	server := map[string]any{}
	if old, ok := cfg["server"].(map[string]any); ok {
		for k, val := range old {
			server[k] = val
		}
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
	raw, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	spec := base.Spec.Template.DeepCopy()
	spec.Labels = labels
	spec.Annotations = nil
	cfgPath := configPath(t, base)
	for i := range spec.Spec.Volumes {
		if spec.Spec.Volumes[i].Name == configVolume(t, base).Name {
			spec.Spec.Volumes[i].ConfigMap.Name = name
		}
	}
	spec.Spec.Volumes = append(spec.Spec.Volumes, corev1.Volume{
		Name:         "e2e-mtls",
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secretName}},
	})
	c := &spec.Spec.Containers[0]
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "e2e-mtls", MountPath: mtlsMountPath, ReadOnly: true})
	c.Resources.Requests = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("10m"),
		corev1.ResourceMemory: resource.MustParse("64Mi"),
	}
	httpOn := fmt.Sprint(!v.httpOff)
	c.Args = overrideFlags(c.Args, map[string]string{
		"config-path":     cfgPath,
		"enable-frontend": httpOn,
		"enable-api":      httpOn,
		// API/frontend replica: leave cleanup and the CRD webhook server to
		// the main controller.
		"enable-cleanup":             "false",
		"enable-webhooks":            "false",
		"enable-validating-webhooks": "false",
	})

	meta := metav1.ObjectMeta{Name: name, Namespace: s.Namespace, Labels: labels}
	s.MustCreateResource(&corev1.ConfigMap{ObjectMeta: meta, Data: map[string]string{path.Base(cfgPath): string(raw)}})
	replicas := int32(1)
	s.MustCreateResource(&appsv1.Deployment{
		ObjectMeta: meta,
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: *spec,
		},
	})
	s.MustCreateResource(&corev1.Service{
		ObjectMeta: meta,
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports:    []corev1.ServicePort{{Name: "https", Port: 8080, TargetPort: intstr.FromInt32(8080)}},
		},
	})
	return name
}

// overrideFlags replaces or appends --name=value flags.
func overrideFlags(args []string, set map[string]string) []string {
	out := make([]string, 0, len(args)+len(set))
	for _, a := range args {
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if _, ok := set[name]; !ok {
			out = append(out, a)
		}
	}
	for k, v := range set {
		out = append(out, "--"+k+"="+v)
	}
	return out
}

func podLogsContain(ctx context.Context, kube kubernetes.Interface, ns, selector, want string) bool {
	pods, err := kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return false
	}
	for _, p := range pods.Items {
		for _, previous := range []bool{false, true} {
			logs, err := kube.CoreV1().Pods(ns).GetLogs(p.Name, &corev1.PodLogOptions{
				Container: p.Spec.Containers[0].Name, Previous: previous,
			}).DoRaw(ctx)
			if err == nil && bytes.Contains(logs, []byte(want)) {
				return true
			}
		}
	}
	return false
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
