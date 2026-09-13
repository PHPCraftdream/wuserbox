package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBundledLibraryIsUsedWhenPresent(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bundled := filepath.Join(filepath.Dir(executable), libraryName)
	if err := os.WriteFile(bundled, []byte("not a real library"), 0o644); err != nil {
		t.Skipf("cannot place a file beside the test binary: %v", err)
	}
	t.Cleanup(func() { os.Remove(bundled) })

	t.Setenv(libraryVariable, "")
	useBundledLibrary()
	if got := os.Getenv(libraryVariable); got != bundled {
		t.Errorf("%s is %q, want %q", libraryVariable, got, bundled)
	}
}

func TestAnExplicitLocationIsKept(t *testing.T) {
	t.Setenv(libraryVariable, `C:\somewhere\ktav.dll`)
	useBundledLibrary()
	if got := os.Getenv(libraryVariable); got != `C:\somewhere\ktav.dll` {
		t.Errorf("the explicit location was replaced by %q", got)
	}
}

func TestNothingHappensWithoutABundledLibrary(t *testing.T) {
	executable, _ := os.Executable()
	if _, err := os.Stat(filepath.Join(filepath.Dir(executable), libraryName)); err == nil {
		t.Skip("a library is present beside the test binary")
	}
	t.Setenv(libraryVariable, "")
	useBundledLibrary()
	if got := os.Getenv(libraryVariable); got != "" {
		t.Errorf("%s was set to %q with no library to point at", libraryVariable, got)
	}
}
