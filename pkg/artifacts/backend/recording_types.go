// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package backend

import "time"

const TerminalRecordingRecipe = "terminal-recording.v1"

// RecordingMetadata contains no credential or provider location.
type RecordingMetadata struct {
	FormatVersion   int32     `json:"formatVersion,omitempty"`
	StartedAt       time.Time `json:"startedAt,omitempty"`
	FinishedAt      time.Time `json:"finishedAt,omitempty"`
	StreamExpiresAt time.Time `json:"streamExpiresAt,omitempty"`
	Complete        bool      `json:"complete,omitempty"`
	Frames          int64     `json:"frames,omitempty"`
	PodNamespace    string    `json:"podNamespace,omitempty"`
	PodName         string    `json:"podName,omitempty"`
	PodUID          string    `json:"podUID,omitempty"`
	ContainerName   string    `json:"containerName,omitempty"`
	Operation       string    `json:"operation,omitempty"`
	LeaseUID        string    `json:"leaseUID,omitempty"`
	LeaseEpoch      string    `json:"leaseEpoch,omitempty"`
	Generation      string    `json:"generation,omitempty"`
}
