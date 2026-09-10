// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package job

import (
	"strings"
	"testing"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
	corev1 "k8s.io/api/core/v1"
)

func testConfig(recipe string) Config {
	return Config{
		Namespace: "breakglass", Name: "dsa-job", ArtifactID: "dsa-0123456789abcdef01234567", ArtifactUID: "artifact-uid-0123456789", SessionNamespace: "breakglass", SessionName: "session", SessionUID: "session-uid-0123456789", Recipe: recipe, RecipeVersion: 1, PlanDigest: strings.Repeat("a", 64), RuntimeBindingDigest: strings.Repeat("b", 64), RedactionProfile: "credential-text.v1", RedactionVersion: 1, UploadURL: "https://breakglass.example/api/debugSessionArtifactUploads/breakglass/session/dsa-0123456789abcdef01234567", UploadToken: "signed-token", Image: "registry.example/collector@sha256:" + strings.Repeat("c", 64), MaxBytes: archive.MaxCollectorArchiveBytes, TimeoutSeconds: 900,
	}
}

func TestBuildSystemSummaryJobHasFixedCommandsAndNoProviderInputs(t *testing.T) {
	config := testConfig(archive.SystemSummaryRecipe)
	config.MaxBytes = archive.MaxSystemSummaryArchiveBytes
	config.DetailLevel = "extended"
	job, err := Build(config)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(job.Spec.Template.Spec.InitContainers) != 1 || len(job.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("collector/uploader ordering = %d init, %d app, want one each", len(job.Spec.Template.Spec.InitContainers), len(job.Spec.Template.Spec.Containers))
	}
	if got := job.Annotations["breakglass.t-caas.telekom.com/plan-sha256"]; got != config.PlanDigest || len(job.Labels["breakglass.t-caas.telekom.com/plan-sha256"]) > 63 {
		t.Fatalf("plan digest annotation/label = %q/%q", got, job.Labels["breakglass.t-caas.telekom.com/plan-sha256"])
	}
	if job.Spec.Template.Spec.SecurityContext == nil || job.Spec.Template.Spec.SecurityContext.FSGroup == nil || *job.Spec.Template.Spec.SecurityContext.FSGroup != 65532 {
		t.Fatal("Job must apply the shared output fsGroup")
	}
	collector := job.Spec.Template.Spec.InitContainers[0]
	if strings.Join(collector.Command, " ") != "/usr/local/bin/diagnostic-artifact-collector collect --recipe system-summary.v1 --output /output/artifact.tar.gz" {
		t.Fatalf("collector command = %q", collector.Command)
	}
	if len(job.Spec.Template.Spec.Volumes) != 1 || job.Spec.Template.Spec.Volumes[0].HostPath != nil {
		t.Fatalf("summary job unexpectedly has a host path")
	}
	for _, container := range append(job.Spec.Template.Spec.InitContainers, job.Spec.Template.Spec.Containers...) {
		for _, env := range container.Env {
			if strings.Contains(strings.ToLower(env.Name), "s3") || strings.Contains(strings.ToLower(env.Name), "credential") || strings.Contains(strings.ToLower(env.Name), "bucket") {
				t.Fatalf("provider configuration leaked into Job env: %s", env.Name)
			}
		}
		if container.SecurityContext == nil || container.SecurityContext.Privileged == nil || *container.SecurityContext.Privileged {
			t.Fatalf("container %q is privileged", container.Name)
		}
	}
}

func TestBuildCrashdumpJobPinsNodeAndReadOnlyHostPath(t *testing.T) {
	config := testConfig(archive.CrashdumpCollectionRecipe)
	config.Node = "worker-one"
	config.MaxAgeMinutes = 60
	job, err := Build(config)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if job.Spec.Template.Spec.NodeName != config.Node {
		t.Fatalf("nodeName = %q, want %q", job.Spec.Template.Spec.NodeName, config.Node)
	}
	var found bool
	for _, volume := range job.Spec.Template.Spec.Volumes {
		if volume.HostPath != nil {
			found = true
			if volume.HostPath.Path != "/var/lib/systemd/coredump" || volume.HostPath.Type == nil || *volume.HostPath.Type != corev1.HostPathDirectory {
				t.Fatalf("unexpected host path volume: %#v", volume.HostPath)
			}
		}
	}
	if !found {
		t.Fatal("crashdump Job has no host coredump volume")
	}
}

func TestBuildRejectsUnpinnedImageAndProviderURL(t *testing.T) {
	config := testConfig(archive.SystemSummaryRecipe)
	config.MaxBytes = archive.MaxSystemSummaryArchiveBytes
	config.Image = "registry.example/collector:latest"
	if _, err := Build(config); err == nil {
		t.Fatal("Build() accepted an unpinned image")
	}
	config = testConfig(archive.SystemSummaryRecipe)
	config.MaxBytes = archive.MaxSystemSummaryArchiveBytes
	config.UploadURL = "https://s3.provider.example/bucket/object"
	if _, err := Build(config); err == nil {
		t.Fatal("Build() accepted a provider upload URL")
	}
}
