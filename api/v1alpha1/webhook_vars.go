// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// webhookClient and webhookCache are populated by each CRD's SetupWebhookWithManager
// and used by validators to perform cluster-scoped checks.
var webhookClient client.Client
var webhookCache cache.Cache
