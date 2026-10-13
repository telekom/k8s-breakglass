// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// DefaultDebugSessionToolboxMountPath is where the toolbox is mounted when the
// template does not set mountPath.
const DefaultDebugSessionToolboxMountPath = "/opt/breakglass/toolbox"

// DebugSessionToolbox mounts an administrator-chosen OCI image as a read-only
// Kubernetes image volume (KEP-4639) into the interactive containers of a
// session: every container of a workload pod, the node debug container and the
// pod-copy debugger container. Ephemeral containers cannot add volumes and are
// not changed. Clusters without the ImageVolume API drop the volume and its
// mounts at admission, so the session still starts without the toolbox.
type DebugSessionToolbox struct {
	// image is the digest-pinned OCI reference of the toolbox image.
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:Pattern=`^[^\s@]+@sha256:[a-f0-9]{64}$`
	Image string `json:"image"`

	// mountPath is the absolute, read-only mount path in each container.
	// The controller exports it as BREAKGLASS_TOOLBOX.
	// +optional
	// +kubebuilder:default="/opt/breakglass/toolbox"
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`
	// +kubebuilder:validation:XValidation:rule="!self.split('/').exists(s, s == '.' || s == '..')",message="mountPath must not contain . or .. segments"
	MountPath string `json:"mountPath,omitempty"`
}

// EffectiveMountPath returns mountPath or the default.
func (t *DebugSessionToolbox) EffectiveMountPath() string {
	if t == nil || t.MountPath == "" {
		return DefaultDebugSessionToolboxMountPath
	}
	return t.MountPath
}
