// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package job

import (
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
)

func TestUploadCABundleIsReadOnlyUploaderOnlyAndAdmissionBound(t *testing.T) {
	for _, recipe := range []string{archive.SystemSummaryRecipe, archive.CrashdumpCollectionRecipe} {
		for _, kind := range []string{"ConfigMap", "Secret"} {
			t.Run(recipe+"/"+kind, func(t *testing.T) {
				config := testConfig(recipe)
				config.MaxBytes = archive.MaxSystemSummaryArchiveBytes
				if recipe == archive.CrashdumpCollectionRecipe {
					config.Node = "worker-one"
				}
				config.UploadCABundleRef = &breakglassv1alpha1.ArtifactUploadCABundleReference{Kind: kind, Name: "upload-ca", Key: "bundle.pem"}
				expected, err := Build(config)
				require.NoError(t, err)
				pod := expected.Spec.Template.Spec
				volume := pod.Volumes[len(pod.Volumes)-1]
				require.Equal(t, "upload-ca", volume.Name)
				if kind == "ConfigMap" {
					require.Equal(t, "upload-ca", volume.ConfigMap.Name)
					require.Equal(t, "bundle.pem", volume.ConfigMap.Items[0].Key)
					require.Equal(t, "ca.crt", volume.ConfigMap.Items[0].Path)
					require.False(t, *volume.ConfigMap.Optional)
				} else {
					require.Equal(t, "upload-ca", volume.Secret.SecretName)
					require.Equal(t, "bundle.pem", volume.Secret.Items[0].Key)
					require.Equal(t, "ca.crt", volume.Secret.Items[0].Path)
					require.False(t, *volume.Secret.Optional)
				}
				for _, mount := range pod.InitContainers[0].VolumeMounts {
					require.NotEqual(t, "upload-ca", mount.Name)
				}
				mount := pod.Containers[0].VolumeMounts[1]
				require.True(t, mount.ReadOnly)
				require.Empty(t, mount.SubPath)
				require.Equal(t, uploadCAMountPath, mount.MountPath)
				require.NoError(t, ValidateExecution(*expected, *expected))
				changed := expected.DeepCopy()
				changed.Spec.Template.Spec.Containers[0].VolumeMounts[1].ReadOnly = false
				require.Error(t, ValidateExecution(*changed, *expected))
				config.UploadCABundleRef.Name = "other-ca"
				changed, err = Build(config)
				require.NoError(t, err)
				require.Error(t, ValidateExecution(*changed, *expected))
			})
		}
	}
}

func TestUploadCABundleRejectsInvalidReferences(t *testing.T) {
	for _, ref := range []*breakglassv1alpha1.ArtifactUploadCABundleReference{
		{Kind: "HostPath", Name: "ca", Key: "ca.pem"},
		{Kind: "Secret", Name: "../ca", Key: "ca.pem"},
		{Kind: "Secret", Name: "ca", Key: "../ca.pem"},
		{Kind: "ConfigMap", Name: "ca"},
	} {
		config := testConfig(archive.SystemSummaryRecipe)
		config.MaxBytes = archive.MaxSystemSummaryArchiveBytes
		config.UploadCABundleRef = ref
		_, err := Build(config)
		require.Error(t, err)
	}
}
