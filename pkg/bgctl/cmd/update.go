package cmd

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/telekom/k8s-breakglass/pkg/version"
)

const (
	defaultRepoAPI = "https://api.github.com/repos/telekom/k8s-breakglass/releases/latest"
)

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

func NewUpdateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update bgctl",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUpdate(cmd, "")
		},
	}

	cmd.AddCommand(
		newUpdateCheckCommand(),
		newUpdateRollbackCommand(),
	)
	cmd.Flags().String("version", "", "Update to specific version tag")
	cmd.Flags().Bool("yes", false, "Skip confirmation")
	cmd.Flags().Bool("dry-run", false, "Show actions without updating")
	return cmd
}

func newUpdateCheckCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check for updates",
		RunE: func(cmd *cobra.Command, _ []string) error {
			release, err := fetchLatestRelease()
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(os.Stdout, "Current version: %s\n", version.Version)
			_, _ = fmt.Fprintf(os.Stdout, "Latest version:  %s\n", release.TagName)
			return nil
		},
	}
}

func newUpdateRollbackCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Rollback to previous version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			versionTag, _ := cmd.Flags().GetString("version")
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			if versionTag != "" {
				return runUpdate(cmd, versionTag)
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			oldPath := exe + ".old"
			if dryRun {
				_, _ = fmt.Fprintf(os.Stdout, "Would rollback to %s\n", oldPath)
				return nil
			}
			if _, err := os.Stat(oldPath); err != nil {
				return fmt.Errorf("rollback binary not found: %s", oldPath)
			}
			return replaceBinary(exe, oldPath)
		},
	}
	cmd.Flags().String("version", "", "Rollback to specific version tag")
	cmd.Flags().Bool("dry-run", false, "Show actions without rollback")
	return cmd
}

func runUpdate(cmd *cobra.Command, versionTag string) error {
	if strings.EqualFold(os.Getenv("BGCTL_DISABLE_UPDATE"), "true") {
		return fmt.Errorf("update disabled by BGCTL_DISABLE_UPDATE")
	}
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	confirm, _ := cmd.Flags().GetBool("yes")

	var release *githubRelease
	var err error
	if versionTag == "" {
		release, err = fetchLatestRelease()
	} else {
		release, err = fetchReleaseByTag(versionTag)
	}
	if err != nil {
		return err
	}
	assetName := assetFileName()
	assetURL := findAssetURL(release.Assets, assetName)
	if assetURL == "" {
		return fmt.Errorf("asset not found for %s", assetName)
	}

	if dryRun {
		_, _ = fmt.Fprintf(os.Stdout, "Would download %s\n", assetURL)
		return nil
	}
	if !confirm {
		_, _ = fmt.Fprintf(os.Stdout, "Updating to %s. Use --yes to skip confirmation.\n", release.TagName)
	}

	tmpDir, err := os.MkdirTemp("", "bgctl-update")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	archivePath := filepath.Join(tmpDir, assetName)
	if err := downloadFile(assetURL, archivePath); err != nil {
		return err
	}

	if err := verifyChecksumIfAvailable(release.Assets, assetName, archivePath); err != nil {
		return err
	}

	extracted, err := extractBinary(archivePath, tmpDir)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return replaceBinary(exe, extracted)
}

func fetchLatestRelease() (*githubRelease, error) {
	resp, err := http.Get(defaultRepoAPI)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch release: %s", string(body))
	}
	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

func fetchReleaseByTag(tag string) (*githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/telekom/k8s-breakglass/releases/tags/%s", strings.TrimPrefix(tag, "v"))
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch release: %s", string(body))
	}
	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

func assetFileName() string {
	os := runtime.GOOS
	arch := runtime.GOARCH
	if os == "windows" {
		return fmt.Sprintf("bgctl_windows_%s.zip", arch)
	}
	return fmt.Sprintf("bgctl_%s_%s.tar.gz", os, arch)
}

func findAssetURL(assets []githubAsset, name string) string {
	for _, asset := range assets {
		if asset.Name == name {
			return asset.URL
		}
	}
	return ""
}

func downloadFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed: %s", string(body))
	}
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	// Use progress writer if content length is known
	if resp.ContentLength > 0 {
		_, err = io.Copy(out, &progressReader{
			reader: resp.Body,
			total:  resp.ContentLength,
		})
	} else {
		_, err = io.Copy(out, resp.Body)
	}
	// Clear the progress line
	if resp.ContentLength > 0 {
		_, _ = fmt.Fprint(os.Stderr, "\r                                                  \r")
	}
	return err
}

// progressReader wraps an io.Reader and prints download progress to stderr.
type progressReader struct {
	reader      io.Reader
	total       int64
	downloaded  int64
	lastPercent int
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	if n > 0 {
		pr.downloaded += int64(n)
		percent := int(float64(pr.downloaded) / float64(pr.total) * 100)
		// Only update display when percent changes to avoid excessive output
		if percent != pr.lastPercent {
			pr.lastPercent = percent
			downloaded := formatBytes(pr.downloaded)
			total := formatBytes(pr.total)
			bar := progressBar(percent, 30)
			_, _ = fmt.Fprintf(os.Stderr, "\r%s %s/%s %d%%", bar, downloaded, total, percent)
		}
	}
	return n, err
}

// progressBar generates a simple ASCII progress bar.
func progressBar(percent, width int) string {
	filled := width * percent / 100
	empty := width - filled
	return "[" + strings.Repeat("=", filled) + strings.Repeat(" ", empty) + "]"
}

// formatBytes formats bytes into a human-readable string.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func verifyChecksumIfAvailable(assets []githubAsset, name, filePath string) error {
	checksumName := name + ".sha256"
	url := findAssetURL(assets, checksumName)
	if url == "" {
		return nil
	}
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return nil
	}
	checksumBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	expected := strings.Fields(string(checksumBytes))
	if len(expected) == 0 {
		return errors.New("empty checksum file")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expected[0] {
		return fmt.Errorf("checksum mismatch: expected %s got %s", expected[0], actual)
	}
	return nil
}

func extractBinary(archivePath, destDir string) (string, error) {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractZip(archivePath, destDir)
	}
	return extractTarGz(archivePath, destDir)
}

func extractTarGz(archivePath, destDir string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = reader.Close()
	}()
	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		// Sanitize archive entry name to prevent path traversal attacks
		safeName := filepath.Base(header.Name)
		if safeName == "" || safeName == "." || safeName == ".." ||
			strings.Contains(safeName, "/") || strings.Contains(safeName, "\\") {
			continue
		}
		if safeName == "bgctl" {
			outPath := filepath.Join(destDir, "bgctl")
			outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				_ = outFile.Close()
				return "", err
			}
			_ = outFile.Close()
			return outPath, nil
		}
	}
	return "", errors.New("bgctl binary not found in archive")
}

func extractZip(archivePath, destDir string) (string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = reader.Close()
	}()
	for _, file := range reader.File {
		// Sanitize archive entry name to prevent Zip Slip attacks
		// First reject entries whose original name contains path traversal patterns
		if file.Name == "" ||
			strings.Contains(file.Name, "..") ||
			strings.Contains(file.Name, "/") ||
			strings.Contains(file.Name, "\\") {
			continue
		}
		// Extract base name and validate it doesn't contain traversal patterns
		safeName := filepath.Base(file.Name)
		if safeName == "" || safeName == "." || safeName == ".." ||
			strings.Contains(safeName, "..") ||
			strings.Contains(safeName, "/") || strings.Contains(safeName, "\\") {
			continue
		}
		// Only extract the expected binary files
		if safeName != "bgctl.exe" && safeName != "bgctl" {
			continue
		}
		outPath, err := extractZipEntry(file, destDir, safeName)
		if err != nil {
			return "", err
		}
		return outPath, nil
	}
	return "", errors.New("bgctl binary not found in archive")
}

// extractZipEntry extracts a single zip entry to the destination directory.
// This is a helper function to avoid defer inside a loop.
func extractZipEntry(file *zip.File, destDir, safeName string) (string, error) {
	rc, err := file.Open()
	if err != nil {
		return "", err
	}
	defer func() {
		_ = rc.Close()
	}()
	outPath := filepath.Join(destDir, safeName)
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(outFile, rc); err != nil {
		_ = outFile.Close()
		return "", err
	}
	_ = outFile.Close()
	return outPath, nil
}

func replaceBinary(target, source string) error {
	backup := target + ".old"
	if err := os.Rename(target, backup); err != nil {
		return err
	}
	if err := copyFile(source, target); err != nil {
		_ = os.Rename(backup, target)
		return err
	}
	return nil
}

func copyFile(src, dst string) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		_ = input.Close()
	}()
	output, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer func() {
		_ = output.Close()
	}()
	_, err = io.Copy(output, input)
	return err
}
