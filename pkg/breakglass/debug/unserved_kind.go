// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// isKindNotServedError reports whether err proves that the API server does not
// serve the requested kind: a RESTMapper NoMatch, or a discovery failure in
// which every failed group-version answered NotFound. Transient discovery
// failures are not proof. A create failing this way never left the client.
func isKindNotServedError(err error) bool {
	var discoveryErr *apiutil.ErrResourceDiscoveryFailed
	if errors.As(err, &discoveryErr) {
		for _, groupErr := range *discoveryErr {
			if !apierrors.IsNotFound(groupErr) && !meta.IsNoMatchError(groupErr) {
				return false
			}
		}
		return len(*discoveryErr) > 0
	}
	return meta.IsNoMatchError(err)
}
