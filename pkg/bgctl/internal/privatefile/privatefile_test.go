package privatefile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteExistingWritableFileInReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	require.NoError(t, os.Chmod(path, 0o600))
	requireUnwritableDir(t, dir)

	require.NoError(t, Write(path, []byte(`{"ok":true}`)))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.JSONEq(t, `{"ok":true}`, string(content))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestWriteDoesNotFollowSymlinkWhenFallingBack(t *testing.T) {
	dir := t.TempDir()
	victimDir := t.TempDir()
	path := filepath.Join(dir, "secret.json")
	victim := filepath.Join(victimDir, "victim.json")
	require.NoError(t, os.WriteFile(victim, []byte(`{"keep":true}`), 0o600))
	if err := os.Symlink(victim, path); err != nil {
		t.Skipf("symlink creation is not permitted in this environment: %v", err)
	}
	requireUnwritableDir(t, dir)

	require.Error(t, Write(path, []byte(`{"replace":true}`)))

	content, err := os.ReadFile(victim)
	require.NoError(t, err)
	require.JSONEq(t, `{"keep":true}`, string(content))
}

func requireUnwritableDir(t *testing.T, dir string) {
	t.Helper()

	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
	})

	probe, err := os.CreateTemp(dir, "probe-*")
	if err == nil {
		_ = probe.Close()
		_ = os.Remove(probe.Name())
		t.Skip("directory write permission is not enforced for this test user")
	}
	require.True(t, os.IsPermission(err), "expected permission error, got %v", err)
}
