// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArtifactUploadCABundleReferenceValidation(t *testing.T) {
	var unset *ArtifactUploadCABundleReference
	require.NoError(t, unset.Validate())
	for _, kind := range []string{"ConfigMap", "Secret"} {
		require.NoError(t, (&ArtifactUploadCABundleReference{Kind: kind, Name: "private-upload-ca", Key: "ca.pem"}).Validate())
	}
	for _, ref := range []*ArtifactUploadCABundleReference{
		{Kind: "Volume", Name: "ca", Key: "ca.pem"},
		{Kind: "Secret", Name: "other/ca", Key: "ca.pem"},
		{Kind: "ConfigMap", Name: strings.Repeat("a", 254), Key: "ca.pem"},
		{Kind: "Secret", Name: "ca", Key: "/ca.pem"},
		{Kind: "ConfigMap", Name: "ca"},
	} {
		require.Error(t, ref.Validate())
		template := &DebugSessionTemplate{Spec: DebugSessionTemplateSpec{
			PodTemplateString:  "apiVersion: v1\nkind: Pod",
			ArtifactCollection: &DebugSessionArtifactCollection{AllowedRecipes: []string{"system-summary.v1"}, UploadCABundleRef: ref},
		}}
		require.Contains(t, validateDebugSessionTemplateSpec(template).ToAggregate().Error(), "artifactCollection.uploadCABundleRef")
	}
}
