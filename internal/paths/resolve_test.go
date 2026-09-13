package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAcceptsEverySpellingOfAnExistingPath(t *testing.T) {
	dir := t.TempDir()
	want, err := Normalize(dir)
	if err != nil {
		t.Fatal(err)
	}
	drive := strings.ToLower(want[:1])
	rest := filepath.ToSlash(want[2:])

	spellings := []string{
		want,
		strings.ToLower(want),
		filepath.ToSlash(want),
		`"` + want + `"`,
		"  " + want + "  ",
		`\\?\` + want,
		want + `\`,
		"/" + drive + rest,
		"/cygdrive/" + drive + rest,
		"/mnt/" + drive + rest,
		filepath.Join(want, "sub", ".."),
	}
	for _, spelling := range spellings {
		got, err := Resolve(spelling)
		if err != nil {
			t.Errorf("%s: %v", spelling, err)
			continue
		}
		if !strings.EqualFold(got, want) {
			t.Errorf("Resolve(%q) = %q, want %q", spelling, got, want)
		}
	}
}

func TestResolveExpandsVariablesAndTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("WUSERBOX_TEST_DIR", home)
	want, err := Normalize(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{
		"~",
		"%USERPROFILE%",
		"$USERPROFILE",
		"${USERPROFILE}",
		"%WUSERBOX_TEST_DIR%",
	} {
		got, err := Resolve(spelling)
		if err != nil {
			t.Errorf("%s: %v", spelling, err)
			continue
		}
		if !strings.EqualFold(got, want) {
			t.Errorf("Resolve(%q) = %q, want %q", spelling, got, want)
		}
	}
}

func TestResolveExpandsTildeWithSubdirectory(t *testing.T) {
	home, err := Normalize(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv("USERPROFILE", home)
	sub := filepath.Join(home, "tools")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{"~/tools", `~\tools`} {
		got, err := Resolve(spelling)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.EqualFold(got, sub) {
			t.Errorf("Resolve(%q) = %q, want %q", spelling, got, sub)
		}
	}
}

func TestResolveHandlesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "child")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	restore, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(sub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(restore) })

	got, err := Resolve("..")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := Normalize(dir)
	if !strings.EqualFold(got, want) {
		t.Errorf("Resolve(\"..\") = %q, want %q", got, want)
	}
}

func TestResolvePrefersTheReadingThatExists(t *testing.T) {
	// A directory literally named "c" next to a drive-letter reading: the one
	// that exists wins, and the drive reading is tried first.
	got, err := Resolve("/c/Windows")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(got, `C:\Windows`) {
		t.Errorf("got %q", got)
	}
}

func TestResolveRejectsEmptyInput(t *testing.T) {
	if _, err := Resolve("   "); err == nil {
		t.Error("expected an error for an empty path")
	}
}

func TestResolveKeepsUnknownPathsUsable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-created-yet")
	got, err := Resolve(filepath.ToSlash(missing))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(got, missing) {
		t.Errorf("got %q, want %q", got, missing)
	}
}
