package cmd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssetFileName_CurrentPlatform(t *testing.T) {
	name := assetFileName()
	if runtime.GOOS == "windows" {
		assert.True(t, strings.HasPrefix(name, "bgctl_windows_"))
		assert.True(t, strings.HasSuffix(name, ".zip"))
	} else {
		assert.True(t, strings.HasPrefix(name, "bgctl_"))
		assert.True(t, strings.HasSuffix(name, ".tar.gz"))
	}
	assert.Contains(t, name, runtime.GOARCH)
}

func TestFindAssetURL(t *testing.T) {
	assets := []githubAsset{
		{Name: "bgctl_darwin_arm64.tar.gz", URL: "https://example.com/darwin"},
		{Name: "bgctl_linux_amd64.tar.gz", URL: "https://example.com/linux"},
	}
	assert.Equal(t, "https://example.com/linux", findAssetURL(assets, "bgctl_linux_amd64.tar.gz"))
	assert.Equal(t, "", findAssetURL(assets, "missing"))
}

func TestProgressBar(t *testing.T) {
	assert.Equal(t, "[     ]", progressBar(0, 5))
	assert.Equal(t, "[==   ]", progressBar(40, 5))
	assert.Equal(t, "[=====]", progressBar(100, 5))
}

func TestFormatBytes(t *testing.T) {
	assert.Equal(t, "0 B", formatBytes(0))
	assert.Equal(t, "1023 B", formatBytes(1023))
	assert.Equal(t, "1.0 KB", formatBytes(1024))
	assert.Equal(t, "1.0 MB", formatBytes(1024*1024))
}

func TestDownloadFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("payload"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "download.bin")

	err := downloadFile(server.URL, path)
	require.NoError(t, err)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(content))
}

func TestDownloadFileErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "download.bin")

	err := downloadFile(server.URL, path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "download failed")
}

func TestVerifyChecksumIfAvailable(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "bgctl.bin")
	require.NoError(t, os.WriteFile(filePath, []byte("hello"), 0o644))

	hash := sha256.Sum256([]byte("hello"))
	checksum := hex.EncodeToString(hash[:]) + "  bgctl.bin\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(checksum))
	}))
	defer server.Close()

	assets := []githubAsset{{Name: "bgctl.bin.sha256", URL: server.URL}}
	err := verifyChecksumIfAvailable(assets, "bgctl.bin", filePath)
	require.NoError(t, err)
}

func TestVerifyChecksumIfAvailableMismatch(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "bgctl.bin")
	require.NoError(t, os.WriteFile(filePath, []byte("hello"), 0o644))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("deadbeef  bgctl.bin\n"))
	}))
	defer server.Close()

	assets := []githubAsset{{Name: "bgctl.bin.sha256", URL: server.URL}}
	err := verifyChecksumIfAvailable(assets, "bgctl.bin", filePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestVerifyChecksumIfAvailableEmptyFile(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "bgctl.bin")
	require.NoError(t, os.WriteFile(filePath, []byte("hello"), 0o644))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	assets := []githubAsset{{Name: "bgctl.bin.sha256", URL: server.URL}}
	err := verifyChecksumIfAvailable(assets, "bgctl.bin", filePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty checksum")
}

func TestVerifyChecksumIfAvailableMissingAsset(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "bgctl.bin")
	require.NoError(t, os.WriteFile(filePath, []byte("hello"), 0o644))

	assets := []githubAsset{}
	err := verifyChecksumIfAvailable(assets, "bgctl.bin", filePath)
	require.NoError(t, err)
}

func TestExtractTarGz(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "bgctl.tar.gz")

	require.NoError(t, writeTarGz(archivePath, map[string]string{
		"bgctl": "binary",
	}))

	outPath, err := extractTarGz(archivePath, tmpDir)
	require.NoError(t, err)
	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "binary", string(content))
}

func TestExtractTarGzNoBinary(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "bgctl.tar.gz")

	require.NoError(t, writeTarGz(archivePath, map[string]string{
		"not-bgctl": "data",
	}))

	_, err := extractTarGz(archivePath, tmpDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bgctl binary not found")
}

func TestExtractTarGzHandlesTraversalName(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "bgctl.tar.gz")

	require.NoError(t, writeTarGz(archivePath, map[string]string{
		"../bgctl": "binary",
	}))

	outPath, err := extractTarGz(archivePath, tmpDir)
	require.NoError(t, err)
	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "binary", string(content))
}

func TestExtractZip(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "bgctl.zip")

	require.NoError(t, writeZip(archivePath, map[string]string{
		"bgctl": "binary",
	}))

	outPath, err := extractZip(archivePath, tmpDir)
	require.NoError(t, err)
	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "binary", string(content))
}

func TestExtractZipExe(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "bgctl.zip")

	require.NoError(t, writeZip(archivePath, map[string]string{
		"bgctl.exe": "binary",
	}))

	outPath, err := extractZip(archivePath, tmpDir)
	require.NoError(t, err)
	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "binary", string(content))
}

func TestExtractZipNoBinary(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "bgctl.zip")

	require.NoError(t, writeZip(archivePath, map[string]string{
		"not-bgctl":    "data",
		"nested/bgctl": "skip",
	}))

	_, err := extractZip(archivePath, tmpDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bgctl binary not found")
}

func TestExtractZipRejectsPaths(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "bgctl.zip")

	require.NoError(t, writeZip(archivePath, map[string]string{
		"dir/bgctl": "should-skip",
	}))

	_, err := extractZip(archivePath, tmpDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bgctl binary not found")
}

func TestReplaceBinary(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "bgctl")
	source := filepath.Join(tmpDir, "bgctl.new")

	require.NoError(t, os.WriteFile(target, []byte("old"), 0o755))
	require.NoError(t, os.WriteFile(source, []byte("new"), 0o755))

	err := replaceBinary(target, source)
	require.NoError(t, err)

	content, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "new", string(content))

	_, err = os.Stat(target + ".old")
	require.NoError(t, err)
}

func writeTarGz(path string, files map[string]string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	gz := gzip.NewWriter(file)
	defer func() {
		_ = gz.Close()
	}()

	tarWriter := tar.NewWriter(gz)
	defer func() {
		_ = tarWriter.Close()
	}()

	for name, content := range files {
		data := []byte(content)
		header := &tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(data)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tarWriter.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func writeZip(path string, files map[string]string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	zipWriter := zip.NewWriter(file)
	defer func() {
		_ = zipWriter.Close()
	}()

	for name, content := range files {
		entry, err := zipWriter.Create(name)
		if err != nil {
			return err
		}
		if _, err := io.Copy(entry, bytes.NewBufferString(content)); err != nil {
			return err
		}
	}
	return nil
}
