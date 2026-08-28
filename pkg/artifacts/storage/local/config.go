// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"errors"
	"path/filepath"
	"strings"
	"time"
)

const (
	AccessModeReadWriteOnce = "ReadWriteOnce"
	StrategyRecreate        = "Recreate"
	SnapshotsProhibited     = "prohibited"
	SnapshotsOutOfScope     = "outside-breakglass-deletion-boundary"

	defaultMaximumObjectBytes = int64(512 << 20)
	sentinelName              = ".breakglass-artifact-instance-v1"
)

// Config is deliberately explicit. Local storage is never selected as a
// fallback when another backend is incomplete or unavailable.
type Config struct {
	ExplicitlyEnabled      bool
	ArtifactRoot           string
	StagingRoot            string
	InstanceID             string
	ExpectedUID            int
	ExpectedGID            int
	ServingReplicas        int
	AccessMode             string
	DeploymentStrategy     string
	EncryptionAcknowledged bool
	SnapshotPolicy         string
	MaximumObjectBytes     int64
	MinimumFreeBytes       int64
	Now                    func() time.Time
}

func (config Config) validate() (Config, error) {
	if !config.ExplicitlyEnabled {
		return config, errors.New("local artifact storage requires an explicit enable switch")
	}
	if !cleanAbsoluteRoot(config.ArtifactRoot) || !cleanAbsoluteRoot(config.StagingRoot) ||
		config.ArtifactRoot == config.StagingRoot || pathContains(config.ArtifactRoot, config.StagingRoot) ||
		pathContains(config.StagingRoot, config.ArtifactRoot) {
		return config, errors.New("local artifact and staging roots must be distinct, unnested, clean absolute paths")
	}
	if !validInstanceID(config.InstanceID) {
		return config, errors.New("local artifact storage instance ID is invalid")
	}
	if config.ExpectedUID < 0 || config.ExpectedGID < 0 || config.ServingReplicas != 1 ||
		config.AccessMode != AccessModeReadWriteOnce || config.DeploymentStrategy != StrategyRecreate {
		return config, errors.New("local artifact storage requires one replica with RWO and Recreate")
	}
	if !config.EncryptionAcknowledged ||
		(config.SnapshotPolicy != SnapshotsProhibited && config.SnapshotPolicy != SnapshotsOutOfScope) {
		return config, errors.New("local artifact storage encryption and snapshot boundaries must be acknowledged")
	}
	if config.MaximumObjectBytes == 0 {
		config.MaximumObjectBytes = defaultMaximumObjectBytes
	}
	if config.MaximumObjectBytes < 1 || config.MaximumObjectBytes > defaultMaximumObjectBytes ||
		config.MinimumFreeBytes < 0 || config.MinimumFreeBytes > (1<<63-1)-headerSize-config.MaximumObjectBytes {
		return config, errors.New("local artifact storage capacity limits are invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return config, nil
}

func cleanAbsoluteRoot(value string) bool {
	return filepath.IsAbs(value) && value != string(filepath.Separator) && filepath.Clean(value) == value &&
		!strings.ContainsRune(value, 0)
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validInstanceID(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("._:-", character) {
			return false
		}
	}
	return true
}
