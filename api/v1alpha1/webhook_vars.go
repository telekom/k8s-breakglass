package v1alpha1

import (
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// webhookClient and webhookCache are populated by each CRD's SetupWebhookWithManager
// and used by validators to perform cluster-scoped checks.
var webhookClient client.Client
var webhookCache cache.Cache
