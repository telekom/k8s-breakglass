// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=hotfixrecords,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=hotfixrecords/status,verbs=get;update;patch

const (
	hotfixJobManager      = "breakglass.t-caas.telekom.com/hotfix"
	hotfixOperationLabel  = "breakglass.t-caas.telekom.com/hotfix-operation"
	hotfixClusterLease    = "breakglass-hotfix"
	hotfixNodeAnnotation  = "hotfix.breakglass.t-caas.telekom.com/"
	hotfixPlanConcurrency = 20
	// hotfixGateTimeout is how long a finished batch may take to become healthy.
	hotfixGateTimeout = 5 * time.Minute
	// hotfixDefaultNodeDeadline bounds one executor when the template sets none.
	hotfixDefaultNodeDeadline = 900
	// hotfixMinNodeTime is the least session time a new executor needs.
	hotfixMinNodeTime = 60 * time.Second
)

// hotfixReadyz checks the API server /readyz endpoint of the target cluster.
// Tests replace it.
var hotfixReadyz = func(ctx context.Context, cfg *rest.Config) error {
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	_, err = clientset.Discovery().RESTClient().Get().AbsPath("/readyz").DoRaw(ctx)
	return err
}

func hotfixIdentity(parts ...string) string {
	digest := sha256.New()
	for _, part := range parts {
		digest.Write([]byte(part))
		digest.Write([]byte{0})
	}
	return "hotfix-" + hex.EncodeToString(digest.Sum(nil))[:24]
}

// hotfixRecordName is the HotfixRecord created by an apply session.
func hotfixRecordName(apply *breakglassv1alpha1.DebugSession) string {
	return hotfixIdentity("record", string(apply.UID))
}

func hotfixMutates(ds *breakglassv1alpha1.DebugSession) bool {
	return ds.Spec.Hotfix != nil && (ds.Spec.Hotfix.Stage == breakglassv1alpha1.HotfixStageApply || ds.Spec.Hotfix.Stage == breakglassv1alpha1.HotfixStageRollback)
}

// hotfixHostShape reports whether a payload needs the privileged host-namespace executor.
func hotfixHostShape(payload *breakglassv1alpha1.HotfixPayload) bool {
	return payload.Type != breakglassv1alpha1.HotfixPayloadNodeFile || len(payload.Restart) != 0
}

// hotfixExecutorRequest mirrors the request read by utils/node-maintenance/cmd/hotfix-action.
type hotfixExecutorRequest struct {
	Stage         string                                  `json:"stage"`
	HotfixID      string                                  `json:"hotfixID"`
	Payload       breakglassv1alpha1.HotfixPayload        `json:"payload"`
	AllowedPaths  []string                                `json:"allowedPaths,omitempty"`
	Restartable   []breakglassv1alpha1.HotfixService      `json:"restartableServices,omitempty"`
	HostContainer *breakglassv1alpha1.HotfixHostContainer `json:"hostContainer,omitempty"`
	Expected      *hotfixExpected                         `json:"expected,omitempty"`
	DeadlineUnix  int64                                   `json:"deadlineUnix"`
}

type hotfixExpected struct {
	BeforeSHA256 string   `json:"beforeSHA256"`
	AfterSHA256  string   `json:"afterSHA256"`
	NewPackages  []string `json:"newPackages,omitempty"`
}

// hotfixExecutorResult mirrors the executor's termination message.
type hotfixExecutorResult struct {
	Result       string   `json:"result"`
	Action       string   `json:"action,omitempty"`
	BeforeSHA256 string   `json:"beforeSHA256,omitempty"`
	AfterSHA256  string   `json:"afterSHA256,omitempty"`
	Diff         string   `json:"diff,omitempty"`
	NewPackages  []string `json:"newPackages,omitempty"`
	Message      string   `json:"message,omitempty"`
}

// hotfixPayload returns the payload this session executes.
func hotfixPayload(ds *breakglassv1alpha1.DebugSession) *breakglassv1alpha1.HotfixPayload {
	if ds.Status.Hotfix != nil && ds.Status.Hotfix.Plan != nil {
		return &ds.Status.Hotfix.Plan.Payload
	}
	return ds.Spec.Hotfix.Payload
}

func (c *DebugSessionController) hotfixRequestJSON(ds *breakglassv1alpha1.DebugSession, node *breakglassv1alpha1.HotfixNodeStatus) (string, error) {
	profile := ds.Status.ResolvedTemplate.Hotfix
	payload := hotfixPayload(ds)
	if payload == nil {
		return "", fmt.Errorf("hotfix payload is missing")
	}
	request := hotfixExecutorRequest{
		Stage: string(ds.Spec.Hotfix.Stage), HotfixID: ds.Status.Hotfix.RecordName,
		Payload: *payload, AllowedPaths: profile.AllowedPaths, Restartable: profile.RestartableServices,
		DeadlineUnix: node.DeadlineUnix,
	}
	if request.HotfixID == "" {
		request.HotfixID = ds.Status.Hotfix.OperationID
	}
	if payload.Image != nil && payload.Image.HostContainer != "" {
		for i := range profile.HostContainers {
			if profile.HostContainers[i].Name == payload.Image.HostContainer {
				request.HostContainer = &profile.HostContainers[i]
			}
		}
	}
	if hotfixMutates(ds) {
		request.Expected = &hotfixExpected{BeforeSHA256: node.BeforeSHA256, AfterSHA256: node.AfterSHA256, NewPackages: node.NewPackages}
	}
	data, err := json.Marshal(request)
	return string(data), err
}

// hotfixPod is the single executor Pod of one node. Its shape is fixed by the payload type.
func (c *DebugSessionController) hotfixPod(ds *breakglassv1alpha1.DebugSession, node *breakglassv1alpha1.HotfixNodeStatus) (*corev1.Pod, error) {
	profile := ds.Status.ResolvedTemplate.Hotfix
	payload := hotfixPayload(ds)
	request, err := c.hotfixRequestJSON(ds, node)
	if err != nil {
		return nil, err
	}
	operation := hotfixIdentity(ds.Status.Hotfix.OperationID, node.UID)
	seconds := node.ActiveDeadlineSeconds
	grace := int64(1)
	if hotfixMutates(ds) {
		// The executor ignores SIGTERM while it mutates; deletion waits for its own deadline.
		grace = seconds
	}
	env := []corev1.EnvVar{
		{Name: "BREAKGLASS_HOTFIX_REQUEST", Value: request},
		{Name: "BREAKGLASS_NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "spec.nodeName"}}},
		{Name: "BREAKGLASS_OPERATION_ID", Value: operation},
	}
	container := corev1.Container{
		Name: "hotfix", Image: profile.ExecutorImage, ImagePullPolicy: corev1.PullIfNotPresent,
		Command: []string{"/usr/local/bin/node-maintenance"}, Args: []string{"hotfix-action"},
		Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
			Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("768Mi")}},
		VolumeMounts: []corev1.VolumeMount{{Name: "evidence", MountPath: "/evidence"}},
	}
	spec := corev1.PodSpec{
		NodeName: node.Name, RestartPolicy: corev1.RestartPolicyNever, AutomountServiceAccountToken: ptr.To(false),
		ActiveDeadlineSeconds: ptr.To(seconds), TerminationGracePeriodSeconds: ptr.To(grace),
		// Explicit, so the API server does not default it to an empty struct
		// that would no longer match the approved executor contract.
		SecurityContext: &corev1.PodSecurityContext{RunAsUser: ptr.To(int64(0)), RunAsGroup: ptr.To(int64(0))},
		// The executor must run on cordoned, tainted and control-plane nodes.
		Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
		Volumes:     []corev1.Volume{{Name: "evidence", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(resource.MustParse("64Mi"))}}}},
	}
	if hotfixHostShape(payload) {
		spec.HostPID, spec.HostNetwork, spec.DNSPolicy = true, true, corev1.DNSClusterFirstWithHostNet
		container.SecurityContext = &corev1.SecurityContext{Privileged: ptr.To(true), RunAsUser: ptr.To(int64(0)), ReadOnlyRootFilesystem: ptr.To(true)}
		env = append(env, corev1.EnvVar{Name: "BREAKGLASS_HOST_EXEC", Value: "nsenter"}, corev1.EnvVar{Name: "BREAKGLASS_HOST_ROOT", Value: "/proc/1/root"})
	} else {
		readOnly := !hotfixMutates(ds)
		dir := path.Dir(payload.File.Path)
		spec.Volumes = append(spec.Volumes,
			corev1.Volume{Name: "target", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: dir, Type: ptr.To(corev1.HostPathDirectory)}}},
			corev1.Volume{Name: "state", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: breakglassv1alpha1.HotfixStateDir, Type: ptr.To(corev1.HostPathDirectoryOrCreate)}}})
		container.VolumeMounts = append(container.VolumeMounts,
			corev1.VolumeMount{Name: "target", MountPath: "/host" + dir, ReadOnly: readOnly},
			corev1.VolumeMount{Name: "state", MountPath: "/host" + breakglassv1alpha1.HotfixStateDir, ReadOnly: readOnly})
		if payload.File.URL != "" && !strings.HasPrefix(dir+"/", "/etc/ssl/certs/") {
			// The executor verifies the download with the node's CA bundle.
			spec.Volumes = append(spec.Volumes, corev1.Volume{Name: "ca", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/ssl/certs", Type: ptr.To(corev1.HostPathDirectory)}}})
			container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{Name: "ca", MountPath: "/host/etc/ssl/certs", ReadOnly: true})
		}
		container.SecurityContext = &corev1.SecurityContext{Privileged: ptr.To(false), AllowPrivilegeEscalation: ptr.To(false),
			ReadOnlyRootFilesystem: ptr.To(true), RunAsUser: ptr.To(int64(0)),
			Capabilities:   &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"CHOWN", "FOWNER", "DAC_OVERRIDE"}},
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}
		env = append(env, corev1.EnvVar{Name: "BREAKGLASS_HOST_ROOT", Value: "/host"})
	}
	container.Env = env
	spec.Containers = []corev1.Container{container}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: operation, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace,
			Labels: map[string]string{DebugSessionLabelKey: ds.Name, hotfixOperationLabel: operation},
			Annotations: map[string]string{"breakglass.t-caas.telekom.com/session-uid": string(ds.UID),
				"breakglass.t-caas.telekom.com/node-uid": node.UID}},
		Spec: spec,
	}, nil
}

// validateHotfixReferences checks at request time that the plan or record a
// stage names exists and fits, so approvers never see a request that cannot run.
func validateHotfixReferences(ctx context.Context, reader ctrlclient.Reader, template *breakglassv1alpha1.DebugSessionTemplate, session *breakglassv1alpha1.DebugSession) error {
	request := session.Spec.Hotfix
	switch request.Stage {
	case breakglassv1alpha1.HotfixStageApply:
		plan := &breakglassv1alpha1.DebugSession{}
		if err := reader.Get(ctx, ctrlclient.ObjectKey{Namespace: session.Namespace, Name: request.PlanRef}, plan); err != nil {
			return fmt.Errorf("planRef %s: %w", request.PlanRef, err)
		}
		return breakglassv1alpha1.ValidateHotfixPlanBinding(template.Spec.Hotfix, session, plan, time.Now().UTC())
	case breakglassv1alpha1.HotfixStageRollback, breakglassv1alpha1.HotfixStageReconfirm, breakglassv1alpha1.HotfixStageClose:
		record := &breakglassv1alpha1.HotfixRecord{}
		if err := reader.Get(ctx, ctrlclient.ObjectKey{Namespace: session.Namespace, Name: request.RecordName}, record); err != nil {
			return fmt.Errorf("recordName %s: %w", request.RecordName, err)
		}
		return hotfixRecordUsable(record, session)
	}
	return nil
}
