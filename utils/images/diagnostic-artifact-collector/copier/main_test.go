// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidRelativePath(t *testing.T) {
	valid := []string{"dump", "nested/core.dump", strings.Repeat("x", maxPathBytes)}
	for _, path := range valid {
		if !validRelativePath(path) {
			t.Errorf("validRelativePath(%q) = false", path)
		}
	}
	invalid := []string{"", ".", "..", "./dump", "nested/../dump", "/dump", "nested//dump", "nested/", "nested\x00dump", strings.Repeat("x", maxPathBytes+1)}
	for _, path := range invalid {
		if validRelativePath(path) {
			t.Errorf("validRelativePath(%q) = true", path)
		}
	}
}

func TestCopyOneSuccessBytesAndMode(t *testing.T) {
	sourceRoot, destinationRoot, sourceDir, destinationDir := testRoots(t)
	defer sourceRoot.Close()
	defer destinationRoot.Close()
	contents := []byte("exact coredump bytes\x00\xff\n")
	writeTestFile(t, filepath.Join(sourceDir, "nested", "panic.dump"), contents)

	if err := copyOne(sourceRoot, destinationRoot, "nested/panic.dump", nil); err != nil {
		t.Fatalf("copyOne() error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destinationDir, "nested", "panic.dump"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(contents) {
		t.Fatalf("copied bytes = %q, want %q", got, contents)
	}
	info, err := os.Stat(filepath.Join(destinationDir, "nested", "panic.dump"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != destinationMode {
		t.Fatalf("destination mode = %04o, want %04o", info.Mode().Perm(), destinationMode)
	}
}

func TestCopyRejectsSourceOutsideSymlink(t *testing.T) {
	sourceRoot, destinationRoot, sourceDir, _ := testRoots(t)
	defer sourceRoot.Close()
	defer destinationRoot.Close()
	external := filepath.Join(t.TempDir(), "outside.dump")
	writeTestFile(t, external, []byte("outside"))
	if err := os.Symlink(external, filepath.Join(sourceDir, "escape.dump")); err != nil {
		t.Fatal(err)
	}

	if err := copyOne(sourceRoot, destinationRoot, "escape.dump", nil); !errors.Is(err, errCopyRejected) {
		t.Fatalf("copyOne() error = %v, want rejection", err)
	}
}

func TestCopyRejectsLeafSymlink(t *testing.T) {
	sourceRoot, destinationRoot, sourceDir, _ := testRoots(t)
	defer sourceRoot.Close()
	defer destinationRoot.Close()
	target := filepath.Join(sourceDir, "target.dump")
	writeTestFile(t, target, []byte("target"))
	if err := os.Symlink(target, filepath.Join(sourceDir, "link.dump")); err != nil {
		t.Fatal(err)
	}

	if err := copyOne(sourceRoot, destinationRoot, "link.dump", nil); !errors.Is(err, errCopyRejected) {
		t.Fatalf("copyOne() error = %v, want rejection", err)
	}
}

func TestCopyRejectsSourceParentSymlinkWithinRoot(t *testing.T) {
	sourceRoot, destinationRoot, sourceDir, _ := testRoots(t)
	defer sourceRoot.Close()
	defer destinationRoot.Close()
	realParent := filepath.Join(sourceDir, "real")
	if err := os.Mkdir(realParent, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(realParent, "dump"), []byte("inside root"))
	if err := os.Symlink(realParent, filepath.Join(sourceDir, "alias")); err != nil {
		t.Fatal(err)
	}

	if err := copyOne(sourceRoot, destinationRoot, "alias/dump", nil); !errors.Is(err, errCopyRejected) {
		t.Fatalf("copyOne() error = %v, want parent symlink rejection", err)
	}
}

func TestCopyRejectsDestinationLeafSymlink(t *testing.T) {
	sourceRoot, destinationRoot, sourceDir, destinationDir := testRoots(t)
	defer sourceRoot.Close()
	defer destinationRoot.Close()
	writeTestFile(t, filepath.Join(sourceDir, "dump"), []byte("source"))
	target := filepath.Join(t.TempDir(), "outside")
	writeTestFile(t, target, []byte("must remain"))
	if err := os.Symlink(target, filepath.Join(destinationDir, "dump")); err != nil {
		t.Fatal(err)
	}

	if err := copyOne(sourceRoot, destinationRoot, "dump", nil); !errors.Is(err, errCopyRejected) {
		t.Fatalf("copyOne() error = %v, want rejection", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "must remain" {
		t.Fatalf("outside target changed to %q", got)
	}
}

func TestCopyRejectsNonRegularSource(t *testing.T) {
	sourceRoot, destinationRoot, sourceDir, _ := testRoots(t)
	defer sourceRoot.Close()
	defer destinationRoot.Close()
	if err := os.Mkdir(filepath.Join(sourceDir, "directory"), 0700); err != nil {
		t.Fatal(err)
	}

	if err := copyOne(sourceRoot, destinationRoot, "directory", nil); !errors.Is(err, errCopyRejected) {
		t.Fatalf("copyOne() error = %v, want rejection", err)
	}
}

func TestCopyRejectsDestinationOutsideSymlinkParent(t *testing.T) {
	sourceRoot, destinationRoot, sourceDir, destinationDir := testRoots(t)
	defer sourceRoot.Close()
	defer destinationRoot.Close()
	writeTestFile(t, filepath.Join(sourceDir, "nested", "dump"), []byte("dump"))
	external := t.TempDir()
	if err := os.Remove(filepath.Join(destinationDir, "nested")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(destinationDir, "nested")); err != nil {
		t.Fatal(err)
	}

	if err := copyOne(sourceRoot, destinationRoot, "nested/dump", nil); !errors.Is(err, errCopyRejected) {
		t.Fatalf("copyOne() error = %v, want rejection", err)
	}
	if _, err := os.Stat(filepath.Join(external, "dump")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside destination was touched: %v", err)
	}
}

func TestCopyRejectsSourceParentSwapAndRemovesPartial(t *testing.T) {
	sourceRoot, destinationRoot, sourceDir, destinationDir := testRoots(t)
	defer sourceRoot.Close()
	defer destinationRoot.Close()
	parent := filepath.Join(sourceDir, "nested")
	writeTestFile(t, filepath.Join(parent, "dump"), []byte("dump"))
	external := t.TempDir()

	err := copyOne(sourceRoot, destinationRoot, "nested/dump", func() {
		if removeErr := os.Remove(filepath.Join(parent, "dump")); removeErr != nil {
			t.Fatal(removeErr)
		}
		if removeErr := os.Remove(parent); removeErr != nil {
			t.Fatal(removeErr)
		}
		if symlinkErr := os.Symlink(external, parent); symlinkErr != nil {
			t.Fatal(symlinkErr)
		}
	})
	if !errors.Is(err, errCopyRejected) {
		t.Fatalf("copyOne() error = %v, want rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(destinationDir, "nested", "dump")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial destination remains: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(external, "dump")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("outside destination was touched: %v", statErr)
	}
}

func TestCopyRejectsExternalHardlink(t *testing.T) {
	sourceRoot, destinationRoot, sourceDir, _ := testRoots(t)
	defer sourceRoot.Close()
	defer destinationRoot.Close()
	source := filepath.Join(sourceDir, "dump")
	writeTestFile(t, source, []byte("hard linked"))
	if err := os.Link(source, filepath.Join(t.TempDir(), "external-link")); err != nil {
		t.Fatal(err)
	}

	if err := copyOne(sourceRoot, destinationRoot, "dump", nil); !errors.Is(err, errCopyRejected) {
		t.Fatalf("copyOne() error = %v, want rejection", err)
	}
}

func TestCopyRejectsSameSizeInPlaceMutation(t *testing.T) {
	sourceRoot, destinationRoot, sourceDir, destinationDir := testRoots(t)
	defer sourceRoot.Close()
	defer destinationRoot.Close()
	source := filepath.Join(sourceDir, "dump")
	writeTestFile(t, source, []byte("before!"))

	err := copyOne(sourceRoot, destinationRoot, "dump", func() {
		if writeErr := os.WriteFile(source, []byte("after!"), 0600); writeErr != nil {
			t.Fatal(writeErr)
		}
	})
	if !errors.Is(err, errCopyRejected) {
		t.Fatalf("copyOne() error = %v, want rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(destinationDir, "dump")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial destination remains: %v", statErr)
	}
}

func TestCopyRejectsDestinationCollisionAndPreservesIt(t *testing.T) {
	sourceRoot, destinationRoot, sourceDir, destinationDir := testRoots(t)
	defer sourceRoot.Close()
	defer destinationRoot.Close()
	writeTestFile(t, filepath.Join(sourceDir, "dump"), []byte("source"))
	destination := filepath.Join(destinationDir, "dump")
	writeTestFile(t, destination, []byte("existing"))

	if err := copyOne(sourceRoot, destinationRoot, "dump", nil); !errors.Is(err, errCopyRejected) {
		t.Fatalf("copyOne() error = %v, want rejection", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing" {
		t.Fatalf("collision destination changed to %q", got)
	}
}

func TestCopyRejectsSizeAndGrowthBounds(t *testing.T) {
	t.Run("initial size", func(t *testing.T) {
		sourceRoot, destinationRoot, sourceDir, destinationDir := testRoots(t)
		defer sourceRoot.Close()
		defer destinationRoot.Close()
		source := filepath.Join(sourceDir, "dump")
		writeTestFile(t, source, []byte("too large"))
		if err := copyOneWithLimit(sourceRoot, destinationRoot, "dump", 4, nil); !errors.Is(err, errCopyRejected) {
			t.Fatalf("copyOne() error = %v, want rejection", err)
		}
		if _, err := os.Stat(filepath.Join(destinationDir, "dump")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("destination created for oversized source: %v", err)
		}
	})

	t.Run("growth after copy", func(t *testing.T) {
		sourceRoot, destinationRoot, sourceDir, destinationDir := testRoots(t)
		defer sourceRoot.Close()
		defer destinationRoot.Close()
		source := filepath.Join(sourceDir, "dump")
		writeTestFile(t, source, []byte("small"))
		err := copyOneWithLimit(sourceRoot, destinationRoot, "dump", 8, func() {
			if truncateErr := os.Truncate(source, 9); truncateErr != nil {
				t.Fatal(truncateErr)
			}
		})
		if !errors.Is(err, errCopyRejected) {
			t.Fatalf("copyOne() error = %v, want rejection", err)
		}
		if _, statErr := os.Stat(filepath.Join(destinationDir, "dump")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("partial destination remains: %v", statErr)
		}
	})
}

func TestOpenOnlyStageRequiresExactlyOneStage(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		output := t.TempDir()
		root, err := os.OpenRoot(output)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if _, err := openOnlyStage(root); !errors.Is(err, errCopyRejected) {
			t.Fatalf("openOnlyStage() error = %v, want rejection", err)
		}
	})
	t.Run("ambiguous", func(t *testing.T) {
		output := t.TempDir()
		if err := os.Mkdir(filepath.Join(output, ".staging.one"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(output, ".staging.two"), 0700); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(output)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if _, err := openOnlyStage(root); !errors.Is(err, errCopyRejected) {
			t.Fatalf("openOnlyStage() error = %v, want rejection", err)
		}
	})
}

func testRoots(t *testing.T) (*os.Root, *os.Root, string, string) {
	t.Helper()
	sourceDir := t.TempDir()
	destinationDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(destinationDir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	sourceRoot, err := os.OpenRoot(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	destinationRoot, err := os.OpenRoot(destinationDir)
	if err != nil {
		sourceRoot.Close()
		t.Fatal(err)
	}
	return sourceRoot, destinationRoot, sourceDir, destinationDir
}

func writeTestFile(t *testing.T, name string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, contents, 0600); err != nil {
		t.Fatal(err)
	}
}
