// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/token"
	"github.com/telekom/k8s-breakglass/pkg/config"
)

func TestBuildDisabledDoesNotReadOrRequireHostDependencies(t *testing.T) {
	components, err := Build(context.Background(), config.Artifacts{}, "not-a-namespace", Dependencies{})
	require.NoError(t, err)
	require.Nil(t, components)
}

func TestLoadKeyringReadsOnlyConfiguredNamespaceAndEnforcesKeyFloor(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tokens", Namespace: "breakglass"}, Data: map[string][]byte{"old": make([]byte, 32), "new": make([]byte, 32)}}).Build()
	keyring, err := loadKeyring(context.Background(), client, "breakglass", "tokens", "new", "https://breakglass.example")
	require.NoError(t, err)
	_, err = keyring.Sign(tokenClaimsForTest())
	require.Error(t, err)
	_, err = loadKeyring(context.Background(), client, "other", "tokens", "new", "https://breakglass.example")
	require.Error(t, err)
}

func TestOpenStoreRejectsMixedBackendsAndCrossNamespaceCredentials(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s3-creds", Namespace: "other"}, Data: map[string][]byte{"accessKeyID": []byte("access"), "secretAccessKey": []byte("secret")}}).Build()
	cfg := config.Artifacts{Backend: "s3", UploadMaxBytes: 1024, S3: &config.ArtifactS3{Region: "eu-central-1", Bucket: "breakglass-artifacts", InstanceID: "instance-0123456789", RequireVersioned: true, CredentialsSecretName: "s3-creds"}, Local: &config.ArtifactLocal{ArtifactRoot: "/a", StagingRoot: "/b"}}
	_, _, err := openStore(context.Background(), cfg, client, "breakglass")
	require.Error(t, err)
	cfg.Local = nil
	_, _, err = openStore(context.Background(), cfg, client, "breakglass")
	require.Error(t, err)
}

func tokenClaimsForTest() token.Claims {
	return token.Claims{Method: "PUT", Route: "/api/debugSessionArtifactUploads/ns/session/dsa-0123456789abcdef01234567", SessionNamespace: "ns", SessionName: "session", SessionUID: "uid", ArtifactID: "dsa-0123456789abcdef01234567", ArtifactPlanDigest: strings.Repeat("a", 64), RuntimeBindingDigest: strings.Repeat("b", 64), TargetIdentityDigest: strings.Repeat("c", 64), OperationEpoch: 1, Recipe: "system-summary.v1", RecipeVersion: 1, JTI: "AAAAAAAAAAAAAAAAAAAAAA"}
}
