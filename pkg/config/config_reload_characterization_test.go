// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPlatformConfigReloadRecovery(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.yaml")
	loader := NewCachedLoader(filename, time.Hour)
	_, err := loader.Get()
	require.ErrorContains(t, err, "config file stat error")
	require.NoError(t, os.WriteFile(filename, []byte("frontend: ["), 0600))
	_, err = loader.Get()
	require.Error(t, err, "initial malformed configuration cannot fall back to a cache")
	baseTime := time.Unix(1700000000, 0)
	write := func(content string, timestamp time.Time) {
		t.Helper()
		require.NoError(t, os.WriteFile(filename, []byte(content), 0600))
		require.NoError(t, os.Chtimes(filename, timestamp, timestamp))
	}
	expireCheck := func() {
		loader.mu.Lock()
		loader.lastCheck = time.Now().Add(-2 * loader.checkEvery)
		loader.mu.Unlock()
	}
	assertURL := func(expected string) {
		t.Helper()
		cfg, getErr := loader.Get()
		require.NoError(t, getErr)
		require.Equal(t, expected, cfg.Frontend.BaseURL)
	}
	write("frontend:\n  baseURL: https://initial.example.com\n", baseTime)
	assertURL("https://initial.example.com")
	write("frontend:\n  baseURL: https://changed.example.com\n", baseTime.Add(time.Second))
	assertURL("https://initial.example.com")
	expireCheck()
	assertURL("https://changed.example.com")
	write("frontend: [", baseTime.Add(2*time.Second))
	expireCheck()
	assertURL("https://changed.example.com")
	// A malformed reload must not advance lastModTime: fixing contents at
	// that same mtime is retried after the next check interval.
	write("frontend:\n  baseURL: https://recovered.example.com\n", baseTime.Add(2*time.Second))
	expireCheck()
	assertURL("https://recovered.example.com")
	require.NoError(t, os.Remove(filename))
	expireCheck()
	assertURL("https://recovered.example.com")
	write("frontend:\n  baseURL: https://recreated.example.com\n", baseTime.Add(3*time.Second))
	expireCheck()
	assertURL("https://recreated.example.com")
	write("frontend:\n  baseURL: https://same-mtime.example.com\n", baseTime.Add(3*time.Second))
	expireCheck()
	assertURL("https://recreated.example.com")
	replacement := filepath.Join(filepath.Dir(filename), "replacement.yaml")
	require.NoError(t, os.WriteFile(replacement, []byte("frontend:\n  baseURL: https://atomic.example.com\n"), 0600))
	require.NoError(t, os.Chtimes(replacement, baseTime.Add(4*time.Second), baseTime.Add(4*time.Second)))
	require.NoError(t, os.Rename(replacement, filename))
	expireCheck()
	assertURL("https://atomic.example.com")
}
