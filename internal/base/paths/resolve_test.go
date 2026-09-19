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

// TestResolveKeepsALiteralDollarInAnExistingName is the regression guard for a
// path that was expanded before anyone asked whether it already named
// something. A directory called project$TAG resolved to project, so a sandbox
// meant for one project was built for another project.
func TestResolveKeepsALiteralDollarInAnExistingName(t *testing.T) {
	for _, name := range []string{"project$WUSERBOX_UNSET", "build%WUSERBOX_UNSET%", "stage${WUSERBOX_UNSET}"} {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		want, err := Normalize(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Resolve(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s resolved to %s", want, got)
		}
	}
}

// TestResolveLeavesAnUnsetVariableAlone covers the path that does not exist
// yet. Replacing an unset name with nothing would turn C:\build\$STAGE into
// C:\build, which is a real directory and the wrong one.
func TestResolveLeavesAnUnsetVariableAlone(t *testing.T) {
	parent := t.TempDir()
	for _, spelling := range []string{"$WUSERBOX_UNSET", "${WUSERBOX_UNSET}", "%WUSERBOX_UNSET%"} {
		got, err := Resolve(filepath.Join(parent, spelling))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got, "WUSERBOX_UNSET") {
			t.Errorf("%s resolved to %s, losing the name that was never set", spelling, got)
		}
	}
}

// TestResolveStillExpandsAVariableThatIsSet keeps the fix from taking the
// expansion away: a name that is set is still replaced, in every spelling.
func TestResolveStillExpandsAVariableThatIsSet(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WUSERBOX_TEST_ROOT", dir)
	want, err := Normalize(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{"$WUSERBOX_TEST_ROOT", "${WUSERBOX_TEST_ROOT}", "%WUSERBOX_TEST_ROOT%"} {
		got, err := Resolve(spelling)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s resolved to %s, want %s", spelling, got, want)
		}
	}
}

// TestResolveReadsTheExtendedLengthUNCForm is the regression guard for the
// network spelling the extended-length prefix can carry. Taking the prefix
// off used to leave "UNC\srv\share" -- marker still in the string, root gone:
// a relative path that could only ever resolve against the current directory,
// never against the machine it names.
func TestResolveReadsTheExtendedLengthUNCForm(t *testing.T) {
	got, err := Resolve(`\\?\UNC\localhost\nosuchshare\dir`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `\\localhost\nosuchshare\dir`; !strings.EqualFold(got, want) {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
}

// TestResolveRefusesDriveRelativePaths turns away the "C:foo" spelling. It
// names something only against the current directory of drive C:, which this
// process does not know for a drive it is not sitting on -- and everything
// downstream would build "<cwd>\C:foo" out of it, a path that is about
// neither the drive nor the directory written.
func TestResolveRefusesDriveRelativePaths(t *testing.T) {
	for _, spelling := range []string{"C:relative", `C:`, "c:relative"} {
		if _, err := Resolve(spelling); err == nil {
			t.Errorf("%s was accepted, and resolves against an unknowable current directory", spelling)
		}
	}
	// A rooted path stays welcome; only the rootless spelling went away.
	if _, err := Resolve(`C:\`); err != nil {
		t.Errorf(`C:\ was refused: %v`, err)
	}
}
