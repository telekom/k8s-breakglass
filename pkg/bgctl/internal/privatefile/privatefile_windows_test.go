// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package privatefile

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestCreateTempPrivateUsesProtectedOwnerACL(t *testing.T) {
	f, err := createTempPrivate(t.TempDir(), ".private-")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	defer os.Remove(path)
	defer f.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	assertProtectedOwnerACL(t, sd)
}

func TestPrivateWriteAndReplacement(t *testing.T) {
	t.Setenv("USERNAME", "Everyone")
	path := filepath.Join(t.TempDir(), "tokens")
	for _, content := range []string{"first secret", "replacement"} {
		if err := Write(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("readback: %q %v", got, err)
		}
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		assertProtectedOwnerACL(t, sd)
	}
}

// Both initial creation and replacement must exclude inherited/group access.
// Resolve the actual token SID; the USERNAME environment variable is untrusted.
func assertProtectedOwnerACL(t *testing.T, sd *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// SDDL may abbreviate a real SID (for example the local administrator as
	// LA). Compare the native ACE SID rather than its display representation.
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL is not protected: %s", sd.String())
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if acl == nil || acl.AceCount != 1 {
		t.Fatalf("expected exactly one ACL entry: %s", sd.String())
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
		t.Fatalf("expected one explicit, non-inheriting allow entry: %s", sd.String())
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !sid.Equals(user.User.Sid) {
		t.Fatalf("ACL grants access to %s instead of process user %s", sid.String(), user.User.Sid.String())
	}
}
