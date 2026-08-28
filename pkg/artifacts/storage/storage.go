// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package storage defines the create-only, exact-version artifact store
// contract. Implementations must fail closed when inventory is ambiguous.
package storage

import (
	"context"
	"errors"
	"io"
	"time"
)

const (
	BackendLocal = "local-v1"
	BackendS3    = "s3-strong-v1"
)

var (
	ErrAlreadyExists = errors.New("artifact object already exists")
	ErrNotFound      = errors.New("artifact object version is not found")
	ErrConflict      = errors.New("artifact object does not match its binding")
	ErrAmbiguous     = errors.New("artifact object inventory is ambiguous")
	ErrBackendDrift  = errors.New("artifact storage backend identity or posture drifted")
)

// Object is the immutable authority for one create-only artifact. Key is an
// opaque, prevalidated digest and never comes from an HTTP path.
type Object struct {
	Key                  string
	RuntimeBindingDigest string
	Size                 int64
	SHA256               string
}

// Metadata identifies one exact durable object version.
type Metadata struct {
	BackendInstanceID    string
	Key                  string
	VersionID            string
	RuntimeBindingDigest string
	Size                 int64
	SHA256               string
	ETag                 string
	ProviderChecksum     string
	ModifiedAt           time.Time
}

// Version is one exact inventory entry. DeleteMarker is meaningful for
// versioned object stores; local storage never creates one.
type Version struct {
	VersionID            string
	DeleteMarker         bool
	RuntimeBindingDigest string
	Size                 int64
	SHA256               string
	ETag                 string
	ProviderChecksum     string
	ModifiedAt           time.Time
}

// Store creates at most one artifact and addresses every subsequent
// operation by exact version. Inventory must return all versions and delete
// markers for the exact key, not merely the current version.
type Store interface {
	Backend() string
	BackendInstanceID() string
	PutIfAbsent(context.Context, Object, io.Reader) (Metadata, error)
	OpenVersion(context.Context, Object, Metadata) (io.ReadCloser, Metadata, error)
	StatVersion(context.Context, Object, Metadata) (Metadata, error)
	Inventory(context.Context, Object) ([]Version, error)
	DeleteVersion(context.Context, Object, Version) error
}
