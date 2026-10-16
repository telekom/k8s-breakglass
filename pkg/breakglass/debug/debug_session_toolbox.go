// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

const (
	toolboxEnvName    = "BREAKGLASS_TOOLBOX"
	toolboxVolumeName = "breakglass-toolbox"
)

// injectToolbox mounts the template toolbox image read-only into the regular
// containers of spec and exports its path as BREAKGLASS_TOOLBOX. When container
// names are given, only those containers are changed (pod copies keep the
// copied application containers as they are). A container that already mounts
// something at the toolbox path keeps its own mount. Init and ephemeral
// containers are never changed. The volume is added only when at least one
// container mounts it.
func injectToolbox(spec *corev1.PodSpec, toolbox *breakglassv1alpha1.DebugSessionToolbox, containers ...string) {
	if spec == nil || toolbox == nil || toolbox.Image == "" {
		return
	}
	mountPath := toolbox.EffectiveMountPath()
	isToolboxVolume := func(v corev1.Volume) bool {
		return v.Image != nil && v.Image.Reference == toolbox.Image
	}
	volumeName := toolboxVolumeName
	for i := 1; slices.ContainsFunc(spec.Volumes, func(v corev1.Volume) bool { return v.Name == volumeName && !isToolboxVolume(v) }); i++ {
		volumeName = fmt.Sprintf("%s-%d", toolboxVolumeName, i)
	}
	mounted := false
	for i := range spec.Containers {
		c := &spec.Containers[i]
		if len(containers) > 0 && !slices.Contains(containers, c.Name) {
			continue
		}
		if slices.ContainsFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool { return m.MountPath == mountPath && m.Name != volumeName }) {
			continue
		}
		c.VolumeMounts = slices.DeleteFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool { return m.Name == volumeName })
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: volumeName, MountPath: mountPath, ReadOnly: true})
		c.Env = slices.DeleteFunc(c.Env, func(e corev1.EnvVar) bool { return e.Name == toolboxEnvName })
		c.Env = append(c.Env, corev1.EnvVar{Name: toolboxEnvName, Value: mountPath})
		mounted = true
	}
	if !mounted {
		return
	}
	spec.Volumes = slices.DeleteFunc(spec.Volumes, func(v corev1.Volume) bool { return v.Name == volumeName })
	spec.Volumes = append(spec.Volumes, corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{Image: &corev1.ImageVolumeSource{
			Reference:  toolbox.Image,
			PullPolicy: corev1.PullIfNotPresent,
		}},
	})
}

// sessionToolbox returns the toolbox of the session's approved template snapshot.
func sessionToolbox(ds *breakglassv1alpha1.DebugSession) *breakglassv1alpha1.DebugSessionToolbox {
	if ds == nil || ds.Status.ResolvedTemplate == nil {
		return nil
	}
	return ds.Status.ResolvedTemplate.Toolbox
}
