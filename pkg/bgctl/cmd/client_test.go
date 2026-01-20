package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

func TestResolveProviderKeyFromClientHelpers(t *testing.T) {
	ctx := &config.Context{Name: "ctx-name"}
	resolved := &config.ResolvedOIDC{ProviderName: "provider"}

	assert.Equal(t, "provider", resolveProviderKey(ctx, resolved))
	assert.Equal(t, "inline:ctx-name", resolveProviderKey(ctx, &config.ResolvedOIDC{}))
	assert.Equal(t, "default", resolveProviderKey(nil, &config.ResolvedOIDC{}))
}

func TestResolveCAFile(t *testing.T) {
	ctxWithCA := &config.Context{CAFile: "/tmp/ctx-ca.pem"}
	rt := &runtimeState{cfg: &config.Config{}}
	assert.Equal(t, "/tmp/ctx-ca.pem", resolveCAFile(ctxWithCA, rt))

	rt.cfg = &config.Config{
		OIDCProviders: []config.OIDCProvider{
			{
				Name:      "provider",
				Authority: "https://example.com",
				ClientID:  "client",
				CAFile:    "/tmp/provider-ca.pem",
			},
		},
	}
	ctxWithProvider := &config.Context{Name: "ctx", OIDCProvider: "provider"}
	assert.Equal(t, "/tmp/provider-ca.pem", resolveCAFile(ctxWithProvider, rt))

	assert.Equal(t, "", resolveCAFile(nil, rt))
}
