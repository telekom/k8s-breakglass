// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	artifactstorage "github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage/local"
)

// terminalRecordingStoreFromEnvironment has no implicit fallback. Operators
// must provision the private roots and sentinel before enabling the backend.
func terminalRecordingStoreFromEnvironment() (artifactstorage.Store, error) {
	if strings.ToLower(strings.TrimSpace(os.Getenv("BREAKGLASS_RECORDING_STORAGE_ENABLED"))) != "true" {
		return nil, nil
	}
	artifactRoot := strings.TrimSpace(os.Getenv("BREAKGLASS_RECORDING_ARTIFACT_ROOT"))
	stagingRoot := strings.TrimSpace(os.Getenv("BREAKGLASS_RECORDING_STAGING_ROOT"))
	instanceID := strings.TrimSpace(os.Getenv("BREAKGLASS_RECORDING_INSTANCE_ID"))
	if artifactRoot == "" || stagingRoot == "" || instanceID == "" {
		return nil, fmt.Errorf("terminal recording storage requires artifact root, staging root, and instance ID")
	}
	uid, err := recordingStorageInt("BREAKGLASS_RECORDING_EXPECTED_UID", os.Getuid())
	if err != nil {
		return nil, err
	}
	gid, err := recordingStorageInt("BREAKGLASS_RECORDING_EXPECTED_GID", os.Getgid())
	if err != nil {
		return nil, err
	}
	if strings.ToLower(strings.TrimSpace(os.Getenv("BREAKGLASS_RECORDING_PRIVATE_ROOT_ACKNOWLEDGED"))) != "true" || strings.ToLower(strings.TrimSpace(os.Getenv("BREAKGLASS_RECORDING_ENCRYPTION_ACKNOWLEDGED"))) != "true" {
		return nil, fmt.Errorf("terminal recording storage requires private-root and encryption acknowledgements")
	}
	snapshotPolicy := strings.TrimSpace(os.Getenv("BREAKGLASS_RECORDING_SNAPSHOT_POLICY"))
	if snapshotPolicy == "" {
		snapshotPolicy = local.SnapshotsProhibited
	}
	return local.Open(local.Config{
		ExplicitlyEnabled: true, PrivateRootAcknowledged: true,
		ArtifactRoot: artifactRoot, StagingRoot: stagingRoot, InstanceID: instanceID,
		ExpectedUID: uid, ExpectedGID: gid, ServingReplicas: 1,
		AccessMode: local.AccessModeReadWriteOnce, DeploymentStrategy: local.StrategyRecreate,
		EncryptionAcknowledged: true, SnapshotPolicy: snapshotPolicy,
	})
}

func recordingStorageInt(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return parsed, nil
}
