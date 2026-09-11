// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package s3 implements the create-only artifact store over an S3-compatible
// object service. Provider configuration is intentionally kept in this
// package; callers receive only the storage.Store contract.
package s3

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

const defaultMaximumObjectBytes = int64(512 << 20)

const sentinelName = ".breakglass-artifact-instance-v1"

// Config contains administrator-owned S3 configuration. None of these values
// are accepted from an artifact request or propagated to a collector Job.
type Config struct {
	Endpoint           string
	Region             string
	Bucket             string
	Prefix             string
	InstanceID         string
	UsePathStyle       bool
	MaximumObjectBytes int64
	RequireVersioned   bool
}

func (config Config) validate() (Config, error) {
	if config.Region == "" || config.Bucket == "" || !validBucket(config.Bucket) {
		return config, errors.New("s3 region and bucket are required and bucket must be bounded")
	}
	if config.Endpoint != "" {
		parsed, err := url.Parse(config.Endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return config, errors.New("s3 endpoint must be an HTTPS origin without path, query, or fragment")
		}
		config.Endpoint = strings.TrimSuffix(config.Endpoint, "/")
	}
	if len(config.InstanceID) < 16 || len(config.InstanceID) > 128 || strings.ContainsAny(config.InstanceID, " \t\r\n") {
		return config, errors.New("s3 backend instance ID is invalid")
	}
	if config.MaximumObjectBytes == 0 {
		config.MaximumObjectBytes = defaultMaximumObjectBytes
	}
	if config.MaximumObjectBytes < 1 || config.MaximumObjectBytes > defaultMaximumObjectBytes {
		return config, errors.New("s3 maximum object size is outside the bounded contract")
	}
	config.Prefix = strings.Trim(config.Prefix, "/")
	if len(config.Prefix) > 256 || strings.ContainsAny(config.Prefix, "\x00\r\n") {
		return config, errors.New("s3 object prefix is invalid")
	}
	if !config.RequireVersioned {
		return config, errors.New("s3 artifact storage requires bucket versioning")
	}
	return config, nil
}

func validBucket(value string) bool {
	if len(value) < 3 || len(value) > 63 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	for _, prefix := range []string{"xn--", "sthree-", "amzn-s3-demo-"} {
		if strings.HasPrefix(value, prefix) {
			return false
		}
	}
	for _, suffix := range []string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"} {
		if strings.HasSuffix(value, suffix) {
			return false
		}
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}
