// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"errors"

	"k8s.io/apimachinery/pkg/util/validation"
)

// ArtifactUploadCABundleReference selects administrator-provisioned upload
// trust in the collector Job's target namespace. It cannot select a file path.
type ArtifactUploadCABundleReference struct {
	// kind is the Kubernetes resource containing the PEM bundle.
	// +kubebuilder:validation:Enum=ConfigMap;Secret
	// +required
	Kind string `json:"kind" yaml:"kind"`
	// name is the resource name in the target namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern="^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$"
	// +required
	Name string `json:"name" yaml:"name"`
	// key contains PEM-encoded CA certificates, not credentials.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern="^[-._a-zA-Z0-9]+$"
	// +required
	Key string `json:"key" yaml:"key"`
}

// Validate also checks startup YAML configuration, which does not pass through
// Kubernetes admission. A nil reference preserves image-pinned system trust.
func (ref *ArtifactUploadCABundleReference) Validate() error {
	if ref == nil {
		return nil
	}
	if (ref.Kind != "ConfigMap" && ref.Kind != "Secret") || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || len(validation.IsConfigMapKey(ref.Key)) != 0 {
		return errors.New("artifact upload CA bundle requires kind ConfigMap or Secret, a valid resource name and a valid key")
	}
	return nil
}
