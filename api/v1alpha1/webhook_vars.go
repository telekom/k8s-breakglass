package v1alpha1

import (
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// webhookClientOnce ensures the webhook client is initialized exactly once,
// preventing race conditions when multiple SetupWebhookWithManager calls occur.
var webhookClientOnce sync.Once

// webhookClient and webhookCache are populated by each CRD's SetupWebhookWithManager
// and used by validators to perform cluster-scoped checks.
// These are protected by webhookClientOnce to prevent race conditions.
var webhookClient client.Client
var webhookCache cache.Cache

// InitWebhookClient initializes the webhook client and cache exactly once.
// This is called by each CRD's SetupWebhookWithManager but only the first call
// actually sets the values, preventing race conditions during parallel setup.
func InitWebhookClient(c client.Client, ca cache.Cache) {
	webhookClientOnce.Do(func() {
		webhookClient = c
		webhookCache = ca
	})
}

// GetWebhookClient returns the webhook client for use in validators.
func GetWebhookClient() client.Client {
	return webhookClient
}

// GetWebhookCache returns the webhook cache for use in validators.
func GetWebhookCache() cache.Cache {
	return webhookCache
}
