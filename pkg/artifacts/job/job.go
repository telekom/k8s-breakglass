// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package job renders the fixed diagnostic collector Job. It accepts only
// typed allowlisted recipe inputs and has no provider configuration surface.
package job

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
)

const (
	collectorContainer = "collector"
	uploaderContainer  = "uploader"
	outputPath         = "/output/artifact.tar.gz"
	uploadURLKey       = "BREAKGLASS_ARTIFACT_UPLOAD_URL"
	uploadTokenKey     = "BREAKGLASS_ARTIFACT_UPLOAD_TOKEN"
)

// Config is the controller-owned rendering input. UploadURL is the Breakglass
// API route only; no storage-provider URL, credential, bucket, or key exists
// in this type.
type Config struct {
	Namespace             string
	Name                  string
	ArtifactID            string
	ArtifactName          string
	ArtifactUID           string
	SessionNamespace      string
	SessionName           string
	SessionUID            string
	Recipe                string
	RecipeVersion         int
	PlanDigest            string
	RuntimeBindingDigest  string
	RedactionProfile      string
	RedactionVersion      int
	UploadURL             string
	UploadToken           string
	UploadTokenSecretName string
	Image                 string
	Node                  string
	MaxBytes              int64
	TimeoutSeconds        int32
	DetailLevel           string
	MaxAgeMinutes         int64
}

// Build renders one Job with fixed commands, paths, identities, and security
// posture. Invalid or incomplete recipes are rejected before rendering.
func Build(config Config) (*batchv1.Job, error) {
	if err := validate(config); err != nil {
		return nil, err
	}
	crashdump := config.Recipe == archive.CrashdumpCollectionRecipe
	labels := map[string]string{
		"breakglass.t-caas.telekom.com/artifact":    config.ArtifactID,
		"breakglass.t-caas.telekom.com/session-uid": config.SessionUID,
		"breakglass.t-caas.telekom.com/plan-sha256": config.PlanDigest,
	}
	env := []corev1.EnvVar{
		{Name: "BREAKGLASS_ARTIFACT_ID", Value: config.ArtifactID},
		{Name: "BREAKGLASS_ARTIFACT_SESSION_NAMESPACE", Value: config.SessionNamespace},
		{Name: "BREAKGLASS_ARTIFACT_SESSION_NAME", Value: config.SessionName},
		{Name: "BREAKGLASS_ARTIFACT_SESSION_UID", Value: config.SessionUID},
		{Name: "BREAKGLASS_ARTIFACT_REDACTION_PROFILE", Value: config.RedactionProfile},
		{Name: "BREAKGLASS_ARTIFACT_REDACTION_VERSION", Value: fmt.Sprintf("%d", config.RedactionVersion)},
		{Name: "BREAKGLASS_ARTIFACT_MAX_BYTES", Value: fmt.Sprintf("%d", config.MaxBytes)},
	}
	if config.DetailLevel != "" {
		env = append(env, corev1.EnvVar{Name: "BREAKGLASS_ARTIFACT_DETAIL_LEVEL", Value: config.DetailLevel})
	}
	if config.MaxAgeMinutes > 0 {
		env = append(env, corev1.EnvVar{Name: "BREAKGLASS_ARTIFACT_MAX_AGE_MINUTES", Value: fmt.Sprintf("%d", config.MaxAgeMinutes)})
	}
	uploaderEnv := append(append([]corev1.EnvVar(nil), env...), corev1.EnvVar{Name: uploadURLKey, Value: config.UploadURL})
	if config.UploadTokenSecretName != "" {
		uploaderEnv = append(uploaderEnv, corev1.EnvVar{Name: uploadTokenKey, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: config.UploadTokenSecretName}, Key: "token", Optional: boolPtr(false)}}})
	} else {
		uploaderEnv = append(uploaderEnv, corev1.EnvVar{Name: uploadTokenKey, Value: config.UploadToken})
	}
	collectorUser := int64(65532)
	if crashdump {
		collectorUser = 0
	}
	collectorSecurity := restrictedSecurityContext(collectorUser)
	uploaderSecurity := restrictedSecurityContext(65532)
	volumes := []corev1.Volume{{Name: "output", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumDefault}}}}
	if crashdump {
		volumes = append(volumes, corev1.Volume{Name: "host-coredumps", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/systemd/coredump", Type: hostPathTypePtr(corev1.HostPathDirectory)}}})
	}
	collectorMounts := []corev1.VolumeMount{{Name: "output", MountPath: "/output"}}
	if crashdump {
		collectorMounts = append(collectorMounts, corev1.VolumeMount{Name: "host-coredumps", MountPath: "/host-coredumps", ReadOnly: true})
	}
	pod := corev1.PodSpec{
		RestartPolicy:                corev1.RestartPolicyNever,
		AutomountServiceAccountToken: boolPtr(false),
		HostNetwork:                  false,
		HostPID:                      false,
		HostIPC:                      false,
		Volumes:                      volumes,
		Containers: []corev1.Container{
			{Name: collectorContainer, Image: config.Image, ImagePullPolicy: corev1.PullIfNotPresent, Command: []string{"/usr/local/bin/diagnostic-artifact-collector", "collect", "--recipe", config.Recipe, "--output", outputPath}, Env: env, SecurityContext: collectorSecurity, VolumeMounts: collectorMounts},
			{Name: uploaderContainer, Image: config.Image, ImagePullPolicy: corev1.PullIfNotPresent, Command: []string{"/usr/local/bin/diagnostic-artifact-collector", "upload", "--archive", outputPath}, Env: uploaderEnv, SecurityContext: uploaderSecurity, VolumeMounts: []corev1.VolumeMount{{Name: "output", MountPath: "/output"}}},
		},
	}
	if crashdump {
		pod.NodeName = config.Node
	}
	if config.TimeoutSeconds > 0 {
		deadline := int64(config.TimeoutSeconds)
		pod.ActiveDeadlineSeconds = &deadline
	}
	controller := true
	blockOwnerDeletion := true
	artifactName := config.ArtifactName
	if artifactName == "" {
		artifactName = config.ArtifactID
	}
	return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: config.Name, Namespace: config.Namespace, Labels: labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "breakglass.t-caas.telekom.com/v1alpha1", Kind: "DebugSessionArtifact", Name: artifactName, UID: types.UID(config.ArtifactUID), Controller: &controller, BlockOwnerDeletion: &blockOwnerDeletion}}}, Spec: batchv1.JobSpec{BackoffLimit: int32Ptr(0), TTLSecondsAfterFinished: int32Ptr(300), Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: pod}}}, nil
}

func validate(config Config) error {
	if len(validation.IsDNS1123Label(config.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(config.Name)) != 0 || (config.ArtifactName != "" && len(validation.IsDNS1123Subdomain(config.ArtifactName)) != 0) || len(validation.IsDNS1123Subdomain(config.SessionNamespace)) != 0 || len(validation.IsDNS1123Subdomain(config.SessionName)) != 0 {
		return errors.New("diagnostic artifact Job identity is invalid")
	}
	if !validArtifactID(config.ArtifactID) || !validOpaque(config.ArtifactUID) || !validOpaque(config.SessionUID) || !validDigest(config.PlanDigest) || !validDigest(config.RuntimeBindingDigest) || config.RedactionProfile == "" || config.RedactionVersion < 1 || config.RecipeVersion < 1 {
		return errors.New("diagnostic artifact Job binding is invalid")
	}
	if config.Recipe != archive.SystemSummaryRecipe && config.Recipe != archive.CrashdumpCollectionRecipe {
		return errors.New("diagnostic artifact recipe is not allowlisted")
	}
	if config.RecipeVersion != 1 || config.MaxBytes < 1 || config.MaxBytes > archive.MaxCollectorArchiveBytes || config.TimeoutSeconds < 1 || config.TimeoutSeconds > 3600 {
		return errors.New("diagnostic artifact Job limits are invalid")
	}
	if config.Recipe == archive.SystemSummaryRecipe && config.MaxBytes > archive.MaxSystemSummaryArchiveBytes {
		return errors.New("system-summary Job limit exceeds its recipe bound")
	}
	if !validImageDigest(config.Image) {
		return errors.New("diagnostic artifact image must be pinned by digest")
	}
	parsed, err := url.Parse(config.UploadURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(config.UploadURL, "provider") {
		return errors.New("diagnostic artifact upload URL must be an HTTPS controller route")
	}
	if config.UploadToken == "" && config.UploadTokenSecretName == "" {
		return errors.New("diagnostic artifact upload token is required")
	}
	if config.Recipe == archive.CrashdumpCollectionRecipe {
		if len(validation.IsDNS1123Subdomain(config.Node)) != 0 || config.Node == "" || config.MaxAgeMinutes < 0 || config.MaxAgeMinutes > 10080 {
			return errors.New("crashdump recipe requires bounded node and age")
		}
	} else if config.Node != "" || config.MaxAgeMinutes != 0 || (config.DetailLevel != "" && config.DetailLevel != "basic" && config.DetailLevel != "extended") {
		return errors.New("system-summary recipe inputs are invalid")
	}
	return nil
}

func restrictedSecurityContext(user int64) *corev1.SecurityContext {
	privileged := false
	allowPrivilegeEscalation := false
	readOnlyRootFilesystem := true
	capabilities := &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}
	seccomp := corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
	group := int64(65532)
	return &corev1.SecurityContext{RunAsUser: &user, RunAsGroup: &group, RunAsNonRoot: boolPtr(user != 0), Privileged: &privileged, AllowPrivilegeEscalation: &allowPrivilegeEscalation, ReadOnlyRootFilesystem: &readOnlyRootFilesystem, Capabilities: capabilities, SeccompProfile: &seccomp}
}

func validArtifactID(value string) bool {
	return len(value) == 28 && strings.HasPrefix(value, "dsa-") && validHex(value[4:])
}
func validDigest(value string) bool { return len(value) == 64 && validHex(value) }
func validHex(value string) bool {
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return value != ""
}
func validOpaque(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, " \t\r\n")
}
func validImageDigest(value string) bool {
	return strings.Contains(value, "@sha256:") && validDigest(value[strings.LastIndex(value, "@sha256:")+8:])
}
func boolPtr(value bool) *bool                                       { return &value }
func int32Ptr(value int32) *int32                                    { return &value }
func hostPathTypePtr(value corev1.HostPathType) *corev1.HostPathType { return &value }
