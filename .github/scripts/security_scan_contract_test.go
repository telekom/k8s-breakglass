// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: CC0-1.0

package securityscan_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestFilesystemScanPolicy(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate workflow contract test")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../workflows/security.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Continue bool `yaml:"continue-on-error"`
			Steps    []struct {
				Name, ID, If, Run, Uses string
				Continue                string `yaml:"continue-on-error"`
				With                    map[string]string
			}
		}
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	job := workflow.Jobs["trivy-fs"]
	if job.Continue {
		t.Fatal("filesystem job must enforce non-PR failures")
	}
	var output string
	foundScan, foundWarning, foundArtifact := false, false, false
	for _, step := range job.Steps {
		switch {
		case step.ID == "trivy_fs":
			foundScan = true
			output = step.With["output"]
			if step.Continue != "${{ github.event_name == 'pull_request' }}" || step.With["exit-code"] != "1" {
				t.Fatal("only PR scans may tolerate failure")
			}
		case step.Name == "Warn about pull request scan findings":
			foundWarning = true
			if step.If != "always() && github.event_name == 'pull_request' && steps.trivy_fs.outcome == 'failure'" {
				t.Fatal("failed PR scans must warn even after scanner failure")
			}
			summary := filepath.Join(t.TempDir(), "summary")
			command := exec.Command("bash", "-e", "-c", step.Run)
			command.Env = append(os.Environ(), "GITHUB_STEP_SUMMARY="+summary)
			annotation, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("warning: %s: %v", annotation, err)
			}
			if !strings.Contains(string(annotation), "::warning title=Trivy filesystem scan::") {
				t.Fatal("missing warning annotation")
			}
			content, err := os.ReadFile(summary)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(content), "trivy-filesystem-results") {
				t.Fatal("missing persistent report guidance")
			}
		case step.With["name"] == "trivy-filesystem-results":
			foundArtifact = true
			if step.With["path"] != output || step.If != "always() && hashFiles('trivy-fs-results.sarif') != ''" {
				t.Fatal("reports must survive scanner failure on every event")
			}
		}
	}
	if !foundScan || !foundWarning || !foundArtifact {
		t.Fatal("incomplete scanner/reporting policy")
	}
}
