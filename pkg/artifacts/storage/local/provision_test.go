//go:build linux || darwin

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	artifactstorage "github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
)

// freshVolumeConfig points both roots at missing directories below an empty
// volume root, as on a newly bound PVC.
func freshVolumeConfig(t *testing.T) Config {
	t.Helper()
	config := localTestConfig(t)
	for _, root := range []string{config.ArtifactRoot, config.StagingRoot} {
		if err := os.Remove(root); err != nil {
			t.Fatal(err)
		}
	}
	return config
}

func TestProvisionFreshVolumeOnceThenOpen(t *testing.T) {
	config := freshVolumeConfig(t)
	if _, err := Open(config); err == nil {
		t.Fatal("Open() accepted an unprovisioned volume")
	}
	result, err := Provision(config)
	if err != nil || result != Provisioned {
		t.Fatalf("Provision() = %q, %v; want %q", result, err, Provisioned)
	}
	for _, root := range []string{config.ArtifactRoot, config.StagingRoot} {
		info, err := os.Stat(root)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode() != os.ModeDir|rootMode {
			t.Fatalf("root %s mode = %v, want %v", root, info.Mode(), os.ModeDir|rootMode)
		}
		assertFileContent(t, filepath.Join(root, sentinelName), []byte(config.InstanceID+"\n"))
	}
	store, err := Open(config)
	if err != nil {
		t.Fatalf("Open() after Provision() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	result, err = Provision(config)
	if err != nil || result != AlreadyProvisioned {
		t.Fatalf("second Provision() = %q, %v; want %q", result, err, AlreadyProvisioned)
	}
}

func TestProvisionAcceptsExistingEmptyPrivateRoots(t *testing.T) {
	config := localTestConfig(t)
	result, err := Provision(config)
	if err != nil || result != Provisioned {
		t.Fatalf("Provision() = %q, %v; want %q", result, err, Provisioned)
	}
}

func TestProvisionRefusesUnsafeVolumes(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, config *Config)
		want    string
	}{
		{
			name: "non-empty root without sentinel",
			prepare: func(t *testing.T, config *Config) {
				if err := os.WriteFile(filepath.Join(config.ArtifactRoot, "object-foreign"), []byte("x"), objectMode); err != nil {
					t.Fatal(err)
				}
			},
			want: "not empty",
		},
		{
			name: "foreign instance sentinel",
			prepare: func(t *testing.T, config *Config) {
				foreign := *config
				foreign.InstanceID = "other-instance-0123456789"
				if err := ProvisionSentinels(foreign); err != nil {
					t.Fatal(err)
				}
			},
			want: artifactstorage.ErrBackendDrift.Error(),
		},
		{
			name: "partially provisioned",
			prepare: func(t *testing.T, config *Config) {
				if err := os.WriteFile(filepath.Join(config.ArtifactRoot, sentinelName), []byte(config.InstanceID+"\n"), sentinelMode); err != nil {
					t.Fatal(err)
				}
			},
			want: "partially provisioned",
		},
		{
			name: "world-writable root",
			prepare: func(t *testing.T, config *Config) {
				if err := os.Chmod(config.StagingRoot, 0o777); err != nil {
					t.Fatal(err)
				}
			},
			want: "ownership or mode is unsafe",
		},
		{
			name: "symlinked root",
			prepare: func(t *testing.T, config *Config) {
				target := filepath.Join(filepath.Dir(config.ArtifactRoot), "elsewhere")
				if err := os.Mkdir(target, rootMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(config.ArtifactRoot); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, config.ArtifactRoot); err != nil {
					t.Fatal(err)
				}
			},
			want: "open local artifact root for provisioning",
		},
		{
			name: "missing volume parent",
			prepare: func(t *testing.T, config *Config) {
				config.ArtifactRoot = filepath.Join(filepath.Dir(config.ArtifactRoot), "absent", "objects")
			},
			want: "open parent directory",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := localTestConfig(t)
			test.prepare(t, &config)
			result, err := Provision(config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Provision() = %q, %v; want error containing %q", result, err, test.want)
			}
			if _, err := os.Lstat(filepath.Join(config.StagingRoot, sentinelName)); test.name != "foreign instance sentinel" && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("Provision() wrote a staging sentinel on a refused volume: %v", err)
			}
		})
	}
}

func TestProvisionRejectsInvalidConfig(t *testing.T) {
	config := freshVolumeConfig(t)
	config.ExplicitlyEnabled = false
	if _, err := Provision(config); err == nil {
		t.Fatal("Provision() accepted an invalid config")
	}
	if _, err := os.Lstat(config.ArtifactRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Provision() created a root for an invalid config: %v", err)
	}
}
