package v1alpha1

import (
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// webhookClientOnce ensures the webhook client is initialized exactly once,
// preventing race conditions when multiple SetupWebhookWithManager calls occur.
var webhookClientOnce sync.Once
var webhookReaderOnce sync.Once

// webhookClient and webhookCache are populated by each CRD's SetupWebhookWithManager
// and used by validators to perform cluster-scoped checks. They are protected by
// webhookClientOnce to prevent race conditions.
var webhookClient client.Client

// webhookReader is initialized separately with the manager's live API reader for
// admission checks that must bypass the informer cache. It is protected by
// webhookReaderOnce to prevent race conditions during parallel setup.
var webhookReader client.Reader
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

// InitWebhookReader initializes the live API reader used by validators that
// must not rely on the informer cache for admission-time uniqueness checks.
func InitWebhookReader(r client.Reader) {
	webhookReaderOnce.Do(func() {
		webhookReader = r
	})
}

// GetWebhookClient returns the webhook client for use in validators.
func GetWebhookClient() client.Client {
	return webhookClient
}

// GetWebhookReader returns the live API reader for validators, falling back to
// the webhook client when no dedicated reader has been configured.
func GetWebhookReader() client.Reader {
	if webhookReader != nil {
		return webhookReader
	}
	return webhookClient
}

// GetWebhookCache returns the webhook cache for use in validators.
func GetWebhookCache() cache.Cache {
	return webhookCache
}
