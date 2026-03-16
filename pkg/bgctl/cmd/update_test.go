package cmd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

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

	err := downloadFile(context.Background(), server.URL, path)
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

	err := downloadFile(context.Background(), server.URL, path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "download failed")
}

func TestDownloadFileHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := downloadFile(ctx, "https://example.com/archive.tar.gz", filepath.Join(t.TempDir(), "download.bin"))
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestDownloadFileUsesDedicatedDownloadClient(t *testing.T) {
	oldAPIClient := updateHTTPClient
	oldDownloadClient := updateDownloadHTTPClient
	t.Cleanup(func() {
		updateHTTPClient = oldAPIClient
		updateDownloadHTTPClient = oldDownloadClient
	})

	apiCalls := 0
	downloadCalls := 0

	updateHTTPClient = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		apiCalls++
		body := io.NopCloser(strings.NewReader("unexpected api client call"))
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: body, Header: make(http.Header)}, nil
	})}

	updateDownloadHTTPClient = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		downloadCalls++
		body := io.NopCloser(strings.NewReader("payload"))
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
	})}

	path := filepath.Join(t.TempDir(), "download.bin")
	err := downloadFile(context.Background(), "https://example.com/archive.tar.gz", path)
	require.NoError(t, err)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(content))
	assert.Equal(t, 0, apiCalls, "metadata client must not be used for binary download")
	assert.Equal(t, 1, downloadCalls, "download client should be used exactly once")
}

func TestFetchReleaseByTagEscapesPathSegment(t *testing.T) {
	oldClient := updateHTTPClient
	t.Cleanup(func() { updateHTTPClient = oldClient })

	var escapedPath string
	updateHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		escapedPath = req.URL.EscapedPath()
		body := io.NopCloser(strings.NewReader(`{"tag_name":"v1.0.0","assets":[]}`))
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       body,
			Header:     make(http.Header),
		}, nil
	})}

	_, err := fetchReleaseByTag(context.Background(), "v1.0.0/../x")
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(escapedPath, "/releases/tags/1.0.0%2F..%2Fx"), "unexpected escaped path: %s", escapedPath)
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
	err := verifyChecksumIfAvailable(context.Background(), assets, "bgctl.bin", filePath)
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
	err := verifyChecksumIfAvailable(context.Background(), assets, "bgctl.bin", filePath)
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
	err := verifyChecksumIfAvailable(context.Background(), assets, "bgctl.bin", filePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty checksum")
}

func TestVerifyChecksumIfAvailableMissingAsset(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "bgctl.bin")
	require.NoError(t, os.WriteFile(filePath, []byte("hello"), 0o644))

	assets := []githubAsset{}
	err := verifyChecksumIfAvailable(context.Background(), assets, "bgctl.bin", filePath)
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

func TestLimitedCopyRejectsOversized(t *testing.T) {
	// Create data larger than the limit
	limit := int64(100)
	data := bytes.Repeat([]byte("x"), int(limit)+1)

	var dst bytes.Buffer
	err := limitedCopy(&dst, bytes.NewReader(data), limit)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")
}

func TestLimitedCopyAllowsExactSize(t *testing.T) {
	limit := int64(100)
	data := bytes.Repeat([]byte("x"), int(limit))

	var dst bytes.Buffer
	err := limitedCopy(&dst, bytes.NewReader(data), limit)
	require.NoError(t, err)
	assert.Equal(t, int(limit), dst.Len())
}

type errAfterDataReader struct {
	data []byte
	err  error
	pos  int
}

func (r *errAfterDataReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func TestLimitedCopyReturnsProbeReadError(t *testing.T) {
	limit := int64(4)
	src := &errAfterDataReader{data: []byte("test"), err: io.ErrUnexpectedEOF}

	var dst bytes.Buffer
	err := limitedCopy(&dst, src, limit)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestExtractTarGzAllowsValidArchive(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	require.NoError(t, writeTarGz(archivePath, map[string]string{
		"bgctl": "small binary",
	}))
	outDir := t.TempDir()
	// Normal extraction should succeed
	result, err := extractTarGz(archivePath, outDir)
	require.NoError(t, err)
	assert.Contains(t, result, "bgctl")
}

func TestExtractZipAllowsValidArchive(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.zip")
	require.NoError(t, writeZip(archivePath, map[string]string{
		"bgctl": "small binary",
	}))
	outDir := t.TempDir()
	// Normal extraction should succeed
	result, err := extractZip(archivePath, outDir)
	require.NoError(t, err)
	assert.Contains(t, result, "bgctl")
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
