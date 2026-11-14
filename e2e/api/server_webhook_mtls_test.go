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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

const webhookListenerPort = 8443

// TestServerWebhookMTLS deploys a server replica with the dedicated
// authorization webhook listener (server.webhook) on :8443 under
// clientAuth: require with per-cluster identity, and the webhook removed
// from the main listener. The client certificates stand in for the
// kube-apiservers of the e2e cluster and of another cluster.
func TestServerWebhookMTLS(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx

	serverCA := newMTLSCA(t, "e2e-webhook-server-ca")
	apiserverCA := newMTLSCA(t, "e2e-webhook-apiserver-ca")
	otherCA := newMTLSCA(t, "e2e-webhook-untrusted-ca")
	expires := time.Now().Add(time.Hour)
	serverCert := serverCA.issue(t, x509.ExtKeyUsageServerAuth, expires)
	ownCluster := apiserverCA.issue(t, x509.ExtKeyUsageClientAuth, expires, s.Cluster)
	otherCluster := apiserverCA.issue(t, x509.ExtKeyUsageClientAuth, expires, "e2e-some-other-cluster")
	wrongCA := otherCA.issue(t, x509.ExtKeyUsageClientAuth, expires, s.Cluster)

	name := "e2e-webhook-mtls" + helpers.GenerateUniqueName("")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.Namespace, Labels: helpers.E2ELabelsWithFeature("server-webhook-mtls")},
		Data: map[string][]byte{
			"tls.crt":      serverCert.certPEM,
			"tls.key":      serverCert.keyPEM,
			"apiserver-ca": apiserverCA.certPEM,
		},
	}
	s.MustCreateResource(secret)
	helpers.DeployServerReplica(t, s, helpers.ServerReplica{
		Name: name,
		EditConfig: func(cfg map[string]any) {
			server, _ := cfg["server"].(map[string]any)
			if server == nil {
				server = map[string]any{}
			}
			server["tlsCertFile"] = mtlsMountPath + "/tls.crt"
			server["tlsKeyFile"] = mtlsMountPath + "/tls.key"
			server["webhook"] = map[string]any{
				"listenAddress":         fmt.Sprintf(":%d", webhookListenerPort),
				"clientAuth":            "require",
				"clientCAFile":          mtlsMountPath + "/apiserver-ca",
				"disableOnMainListener": true,
			}
			cfg["server"] = server
		},
		Flags: map[string]string{"enable-frontend": "true", "enable-api": "true"},
		Volumes: []corev1.Volume{{
			Name:         "e2e-mtls",
			VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret.Name}},
		}},
		VolumeMounts: []corev1.VolumeMount{{Name: "e2e-mtls", MountPath: mtlsMountPath, ReadOnly: true}},
		Ports:        []int32{webhookListenerPort},
	})
	require.NoError(t, helpers.WaitForDeploymentReady(ctx, s.Client, s.Namespace, name, 5*time.Minute))

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(serverCA.cert)
	// kubectl port-forward exits when the server resets a rejected
	// handshake, so every request gets its own forward.
	baseURL := func(t *testing.T, port int) string {
		local, stop := helpers.StartPortForward(t, ctx, s.Namespace, name, port, 0)
		t.Cleanup(stop)
		return fmt.Sprintf("https://localhost:%d", local)
	}
	sar, err := json.Marshal(authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:               helpers.GetTestUserEmail(),
			ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "get", Resource: "pods", Namespace: "default"},
		},
	})
	require.NoError(t, err)
	authorize := func(t *testing.T, port int, cert *tls.Certificate, path string) (int, []byte) {
		t.Helper()
		status, body, err := mtlsDo(ctx, mtlsHTTPClient(mtlsTLSConfig(rootCAs, cert, &atomic.Bool{})), http.MethodPost, baseURL(t, port)+path, "", sar)
		require.NoError(t, err)
		return status, body
	}
	paths := []string{"/api/breakglass/webhook/authorize/" + s.Cluster, "/breakglass/webhook/authorize/" + s.Cluster}

	t.Run("wrong-ca", func(t *testing.T) {
		cfg := mtlsTLSConfig(rootCAs, &wrongCA.tls, &atomic.Bool{})
		cfg.MaxVersion = tls.VersionTLS12 // the verdict is part of the handshake
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp",
			baseURL(t, webhookListenerPort)[len("https://"):], cfg)
		if err == nil {
			_ = conn.Close()
		}
		assert.ErrorContains(t, err, "tls: unknown certificate authority")
	})

	t.Run("no-cert", func(t *testing.T) {
		cfg := mtlsTLSConfig(rootCAs, nil, &atomic.Bool{})
		cfg.MaxVersion = tls.VersionTLS12
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp",
			baseURL(t, webhookListenerPort)[len("https://"):], cfg)
		if err == nil {
			_ = conn.Close()
		}
		assert.Error(t, err, "clientAuth: require must reject a handshake without a certificate")
	})

	t.Run("other-cluster-cert", func(t *testing.T) {
		for _, path := range paths {
			status, body := authorize(t, webhookListenerPort, &otherCluster.tls, path)
			assert.Equal(t, http.StatusForbidden, status, "%s: %s", path, body)
		}
	})

	t.Run("own-cluster-cert", func(t *testing.T) {
		for _, path := range paths {
			status, body := authorize(t, webhookListenerPort, &ownCluster.tls, path)
			require.Equal(t, http.StatusOK, status, "%s: %s", path, body)
			var got authorizationv1.SubjectAccessReview
			require.NoError(t, json.Unmarshal(body, &got))
			assert.False(t, got.Status.Allowed, "a user without a session must not be allowed")
		}
	})

	t.Run("webhook-listener-serves-only-the-webhook", func(t *testing.T) {
		status, _, err := mtlsDo(ctx, mtlsHTTPClient(mtlsTLSConfig(rootCAs, &ownCluster.tls, &atomic.Bool{})),
			http.MethodGet, baseURL(t, webhookListenerPort)+"/api/config", "", nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("disabled-on-main-listener", func(t *testing.T) {
		for _, path := range paths {
			status, body := authorize(t, 8080, nil, path)
			assert.Equal(t, http.StatusNotFound, status, "%s: %s", path, body)
		}
		// The rest of the main listener is unchanged.
		status, _, err := mtlsDo(ctx, mtlsHTTPClient(mtlsTLSConfig(rootCAs, nil, &atomic.Bool{})),
			http.MethodGet, baseURL(t, 8080)+"/api/config", "", nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
	})
}
