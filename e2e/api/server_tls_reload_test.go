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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestServerTLSReload rotates the serving certificate and the client CA in
// the mounted Secret of a running HTTPS server with clientAuth: require and
// expects new connections to use them without a pod restart.
func TestServerTLSReload(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx

	serverCA := newMTLSCA(t, "e2e-reload-server-ca")
	oldClientCA := newMTLSCA(t, "e2e-reload-old-client-ca")
	newClientCA := newMTLSCA(t, "e2e-reload-new-client-ca")
	oldServer := serverCA.issue(t, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))
	newServer := serverCA.issue(t, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))
	oldClient := oldClientCA.issue(t, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))
	newClient := newClientCA.issue(t, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))
	oldLeaf, err := x509.ParseCertificate(oldServer.tls.Certificate[0])
	require.NoError(t, err)
	newLeaf, err := x509.ParseCertificate(newServer.tls.Certificate[0])
	require.NoError(t, err)

	name := "e2e-tls-reload" + helpers.GenerateUniqueName("")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.Namespace, Labels: helpers.E2ELabelsWithFeature("server-tls-reload")},
		Data: map[string][]byte{
			"tls.crt":   oldServer.certPEM,
			"tls.key":   oldServer.keyPEM,
			"client-ca": oldClientCA.certPEM,
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
			server["clientAuth"] = "require"
			server["clientCAFile"] = mtlsMountPath + "/client-ca"
			cfg["server"] = server
		},
		Flags: map[string]string{"enable-frontend": "true", "enable-api": "true"},
		Volumes: []corev1.Volume{{
			Name:         "e2e-mtls",
			VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret.Name}},
		}},
		VolumeMounts: []corev1.VolumeMount{{Name: "e2e-mtls", MountPath: mtlsMountPath, ReadOnly: true}},
	})
	require.NoError(t, helpers.WaitForDeploymentReady(ctx, s.Client, s.Namespace, name, 5*time.Minute))
	podsBefore := serverReplicaPods(t, ctx, s, name)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(serverCA.cert)
	// handshake returns the serving certificate serial. kubectl port-forward
	// exits when the server resets a rejected handshake, so every handshake
	// gets its own forward. TLS 1.2 makes the client-certificate verdict part
	// of the handshake.
	handshake := func(client mtlsLeaf) (*big.Int, error) {
		port, stop := helpers.StartPortForward(t, ctx, s.Namespace, name, 8080, 0)
		defer stop()
		cfg := mtlsTLSConfig(rootCAs, &client.tls, &atomic.Bool{})
		cfg.MaxVersion = tls.VersionTLS12
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", fmt.Sprintf("localhost:%d", port), cfg)
		if err != nil {
			return nil, err
		}
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber, nil
	}

	serial, err := handshake(oldClient)
	require.NoError(t, err)
	assert.Equal(t, 0, serial.Cmp(oldLeaf.SerialNumber), "initial serving certificate")
	_, err = handshake(newClient)
	require.ErrorContains(t, err, "tls: unknown certificate authority")

	secret.Data = map[string][]byte{
		"tls.crt":   newServer.certPEM,
		"tls.key":   newServer.keyPEM,
		"client-ca": newClientCA.certPEM,
	}
	require.NoError(t, s.Client.Update(ctx, secret))

	// The kubelet syncs the Secret volume within about a minute; the server
	// then picks the files up within its 10s poll interval.
	var lastErr error
	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 3*time.Minute, true, func(context.Context) (bool, error) {
		serial, err := handshake(newClient)
		if err != nil {
			lastErr = err
			return false, nil
		}
		if serial.Cmp(newLeaf.SerialNumber) != 0 {
			lastErr = fmt.Errorf("serving serial %s, want %s", serial, newLeaf.SerialNumber)
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err, "rotated certificate and client CA not served; last attempt: %v", lastErr)

	_, err = handshake(oldClient)
	assert.ErrorContains(t, err, "tls: unknown certificate authority", "the replaced client CA must no longer be trusted")
	podsAfter := serverReplicaPods(t, ctx, s, name)
	assert.Equal(t, podsBefore, podsAfter, "the server must not restart to pick up the rotated files")
}

// serverReplicaPods returns pod name to total container restarts.
func serverReplicaPods(t *testing.T, ctx context.Context, s *helpers.TestSetup, name string) map[string]int32 {
	t.Helper()
	var pods corev1.PodList
	require.NoError(t, s.Client.List(ctx, &pods, client.InNamespace(s.Namespace),
		client.MatchingLabels{helpers.ServerReplicaLabel: name}))
	require.NotEmpty(t, pods.Items)
	out := map[string]int32{}
	for _, p := range pods.Items {
		for _, cs := range p.Status.ContainerStatuses {
			out[p.Name] += cs.RestartCount
		}
	}
	return out
}
