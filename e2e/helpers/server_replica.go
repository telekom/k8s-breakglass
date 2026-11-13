/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package helpers

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// ServerReplicaLabel selects the pods of one server replica.
const ServerReplicaLabel = "e2e-server-replica"

// ServerReplica is an extra breakglass API/frontend replica that runs the
// image, service account and config.yaml of the controller under test, with
// changes. It follows the API-only pattern in
// docs/scaling-and-leader-election.md: reconcilers, cleanup and the CRD
// webhook server stay with the main controller, and the replica uses its own
// leader-election lease so it never competes with the main controller.
type ServerReplica struct {
	// Name of the ConfigMap, Deployment and Service (port 8080).
	Name string
	// EditConfig changes the parsed config.yaml in place.
	EditConfig func(cfg map[string]any)
	// Flags adds or overrides --name=value controller flags.
	Flags        map[string]string
	Volumes      []corev1.Volume
	VolumeMounts []corev1.VolumeMount
	// Ports are extra container ports the Service exposes next to 8080.
	Ports []int32
}

// DeployServerReplica creates the replica and registers it for cleanup. It
// does not wait for readiness. Pod labels are replaced, so the main breakglass
// Service never routes to the replica.
func DeployServerReplica(t *testing.T, s *TestSetup, r ServerReplica) {
	t.Helper()
	base := mainControllerDeployment(t, s.Ctx, s.Client, s.Namespace)
	spec := base.Spec.Template.DeepCopy()
	c := &spec.Spec.Containers[0]
	cfgPath := flagValue(c.Args, "config-path")
	require.NotEmpty(t, cfgPath, "controller has no --config-path flag")
	cfgVolume := configMapVolume(t, spec, path.Dir(cfgPath))

	var cm corev1.ConfigMap
	require.NoError(t, s.Client.Get(s.Ctx, client.ObjectKey{Namespace: s.Namespace, Name: cfgVolume.ConfigMap.Name}, &cm))
	var cfg map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(cm.Data[path.Base(cfgPath)]), &cfg))
	if r.EditConfig != nil {
		r.EditConfig(cfg)
	}
	raw, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	labels := E2ELabelsWithExtra(map[string]string{ServerReplicaLabel: r.Name})
	spec.Labels = labels
	spec.Annotations = nil
	cfgVolume.ConfigMap.Name = r.Name
	spec.Spec.Volumes = append(spec.Spec.Volumes, r.Volumes...)
	c.VolumeMounts = append(c.VolumeMounts, r.VolumeMounts...)
	c.Resources.Requests = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("50m"),
		corev1.ResourceMemory: resource.MustParse("128Mi"),
	}
	flags := map[string]string{
		"enable-controllers":         "false",
		"enable-cleanup":             "false",
		"leader-elect-id":            r.Name,
		"enable-webhooks":            "false",
		"enable-validating-webhooks": "false",
	}
	for k, v := range r.Flags {
		flags[k] = v
	}
	c.Args = OverrideFlags(c.Args, flags)

	ports := []corev1.ServicePort{{Name: "http", Port: 8080, TargetPort: intstr.FromInt32(8080)}}
	for _, p := range r.Ports {
		ports = append(ports, corev1.ServicePort{Name: fmt.Sprintf("port-%d", p), Port: p, TargetPort: intstr.FromInt32(p)})
	}
	meta := metav1.ObjectMeta{Name: r.Name, Namespace: s.Namespace, Labels: labels}
	s.MustCreateResource(&corev1.ConfigMap{ObjectMeta: meta, Data: map[string]string{path.Base(cfgPath): string(raw)}})
	replicas := int32(1)
	s.MustCreateResource(&appsv1.Deployment{
		ObjectMeta: meta,
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: *spec,
		},
	})
	s.MustCreateResource(&corev1.Service{
		ObjectMeta: meta,
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports:    ports,
		},
	})
}

// ServerReplicaLogsContain reports whether the current or previous container
// log of any pod of the replica contains want.
func ServerReplicaLogsContain(t *testing.T, ctx context.Context, namespace, name, want string) bool {
	t.Helper()
	kube, err := kubernetes.NewForConfig(GetConfig(t))
	require.NoError(t, err)
	pods, err := kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: ServerReplicaLabel + "=" + name})
	if err != nil {
		return false
	}
	for _, p := range pods.Items {
		for _, previous := range []bool{false, true} {
			logs, err := kube.CoreV1().Pods(namespace).GetLogs(p.Name, &corev1.PodLogOptions{
				Container: p.Spec.Containers[0].Name, Previous: previous,
			}).DoRaw(ctx)
			if err == nil && bytes.Contains(logs, []byte(want)) {
				return true
			}
		}
	}
	return false
}

// OverrideFlags replaces or appends --name=value flags.
func OverrideFlags(args []string, set map[string]string) []string {
	out := make([]string, 0, len(args)+len(set))
	for _, a := range args {
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if _, ok := set[name]; !ok {
			out = append(out, a)
		}
	}
	for k, v := range set {
		out = append(out, "--"+k+"="+v)
	}
	return out
}

func flagValue(args []string, name string) string {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
			return v
		}
	}
	return ""
}

// mainControllerDeployment returns the controller under test.
func mainControllerDeployment(t *testing.T, ctx context.Context, cli client.Client, namespace string) *appsv1.Deployment {
	t.Helper()
	var list appsv1.DeploymentList
	require.NoError(t, cli.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabels{"app": "breakglass"}))
	require.Len(t, list.Items, 1, "expected exactly one breakglass controller deployment")
	return &list.Items[0]
}

func configMapVolume(t *testing.T, spec *corev1.PodTemplateSpec, dir string) *corev1.Volume {
	t.Helper()
	for _, m := range spec.Spec.Containers[0].VolumeMounts {
		if path.Clean(m.MountPath) != dir {
			continue
		}
		for i := range spec.Spec.Volumes {
			if v := &spec.Spec.Volumes[i]; v.Name == m.Name && v.ConfigMap != nil {
				return v
			}
		}
	}
	t.Fatalf("no ConfigMap volume mounted at %s", dir)
	return nil
}
