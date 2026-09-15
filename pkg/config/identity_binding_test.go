// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLegacyIdentityRequiresUniqueConfiguredProvider(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	a := &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "a"}, Spec: breakglassv1alpha1.IdentityProviderSpec{Issuer: "https://a.example/"}}
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(a).Build()
	require.True(t, IsOnlyEnabledIdentityProvider(context.Background(), cli, "a", "https://a.example"))
	require.False(t, IsOnlyEnabledIdentityProvider(context.Background(), cli, "b", "https://a.example"))
	require.False(t, IsOnlyEnabledIdentityProvider(context.Background(), cli, "a", ""))
	// Authority-only providers use the same effective issuer as authentication.
	a.Spec.Issuer = ""
	a.Spec.OIDC.Authority = "https://a.example/"
	require.NoError(t, cli.Update(context.Background(), a))
	require.True(t, IsOnlyEnabledIdentityProvider(context.Background(), cli, "a", "https://a.example"))
	a.Spec.Issuer = "https://explicit.example"
	require.NoError(t, cli.Update(context.Background(), a))
	require.False(t, IsOnlyEnabledIdentityProvider(context.Background(), cli, "a", "https://a.example"))
	a.Spec.Issuer = ""
	require.NoError(t, cli.Update(context.Background(), a))
	// An invalid second provider still makes identity provenance ambiguous.
	b := &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "b"}}
	require.NoError(t, cli.Create(context.Background(), b))
	require.False(t, IsOnlyEnabledIdentityProvider(context.Background(), cli, "a", "https://a.example"))
	b.Spec.Disabled = true
	require.NoError(t, cli.Update(context.Background(), b))
	require.True(t, IsOnlyEnabledIdentityProvider(context.Background(), cli, "a", "https://a.example"))
}

// Provider selection and legacy compatibility have different ambiguity rules:
// an issuer can select one provider in a multi-provider deployment, while an
// unbound historical principal still cannot be attributed safely.
func TestIssuerSelectionDoesNotImplyLegacyIdentityCompatibility(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	a := &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "a"}, Spec: breakglassv1alpha1.IdentityProviderSpec{OIDC: breakglassv1alpha1.OIDCConfig{Authority: "https://a.example", ClientID: "client", ExpectedAudience: "client"}}}
	b := a.DeepCopy()
	b.Name = "b"
	b.Spec.OIDC.Authority = "https://b.example"
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(a, b).Build()
	loader := NewIdentityProviderLoader(cli)
	selected, err := loader.LoadIdentityProviderByIssuer(ctx, "https://a.example/")
	require.NoError(t, err)
	require.Equal(t, "a", selected.Name)
	require.False(t, loader.AllowsLegacyIdentity(ctx, selected.Name, "https://a.example"))
	b.Spec.Disabled = true
	require.NoError(t, cli.Update(ctx, b))
	require.True(t, loader.AllowsLegacyIdentity(ctx, selected.Name, "https://a.example"))
	b.Spec.Disabled = false
	b.Spec.Issuer = "https://a.example"
	require.NoError(t, cli.Update(ctx, b))
	_, err = loader.LoadIdentityProviderByIssuer(ctx, "https://a.example")
	require.ErrorContains(t, err, "multiple enabled IdentityProviders")
	require.False(t, loader.AllowsLegacyIdentity(ctx, "a", "https://a.example"))
}
