package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// useProfile points the config package and paths.Home at fresh temporary
// directories and writes a rules file whose profile section is entries, the
// way a hand-edited or pre-filled rules file would.
func useProfile(t *testing.T, entries []string) (home, dest string) {
	t.Helper()
	home = t.TempDir()
	dest = filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	if err := (&config.Config{Profile: entries}).Save(); err != nil {
		t.Fatal(err)
	}
	return home, dest
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCopyPlacesListedEntriesAtTheSameRelativeSpot(t *testing.T) {
	home, dest := useProfile(t, []string{".claude", ".gitconfig"})
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"a":1}`)
	write(t, filepath.Join(home, ".gitconfig"), "[user]\n")

	copied, err := Copy(dest)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(copied)
	if !reflect.DeepEqual(copied, []string{".claude", ".gitconfig"}) {
		t.Errorf("reported %v", copied)
	}
	if got := read(t, filepath.Join(dest, ".claude", "settings.json")); got != `{"a":1}` {
		t.Errorf("the copy holds %q", got)
	}
	if got := read(t, filepath.Join(dest, ".gitconfig")); got != "[user]\n" {
		t.Errorf("the copy holds %q", got)
	}
}

func TestCopySkipsMissingEntriesWithoutError(t *testing.T) {
	home, dest := useProfile(t, []string{".claude", ".codex"})
	write(t, filepath.Join(home, ".claude", "settings.json"), "{}")

	copied, err := Copy(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(copied, []string{".claude"}) {
		t.Errorf("reported %v, the missing entry should have been left out silently", copied)
	}
	if _, err := os.Stat(filepath.Join(dest, ".codex")); err == nil {
		t.Error("a name that does not exist on this machine was copied anyway")
	}
}

// TestCopyNeverTouchesTheSource is the guard for the one-way rule: nothing a
// caller can do with the copy - including editing it - is allowed to reach
// back into what it came from.
func TestCopyNeverTouchesTheSource(t *testing.T) {
	home, dest := useProfile(t, []string{".gitconfig"})
	write(t, filepath.Join(home, ".gitconfig"), "[user]\n\tname = real\n")

	if _, err := Copy(dest); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dest, ".gitconfig"), "[user]\n\tname = tampered\n")

	if _, err := Copy(dest); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(home, ".gitconfig")); got != "[user]\n\tname = real\n" {
		t.Errorf("the source changed to %q", got)
	}
}

// TestCopyReconcilesADirectoryToMatchItsSource covers the freshness rule:
// copying is unconditional, so a directory's copy is remade to match its
// source exactly on every call, discarding whatever was added to the copy
// and restoring whatever the copy's own edits overwrote.
func TestCopyReconcilesADirectoryToMatchItsSource(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"v":1}`)
	if _, err := Copy(dest); err != nil {
		t.Fatal(err)
	}

	write(t, filepath.Join(dest, ".claude", "settings.json"), `{"v":"tampered"}`)
	write(t, filepath.Join(dest, ".claude", "stray.txt"), "left behind by a run")

	if _, err := Copy(dest); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dest, ".claude", "settings.json")); got != `{"v":1}` {
		t.Errorf("the edited copy was kept: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dest, ".claude", "stray.txt")); !os.IsNotExist(err) {
		t.Error("a file the source does not have survived a copy")
	}
}

// TestCopyDropsEntriesRemovedFromTheList covers pruning: editing an entry
// out of the rules file must also remove what an earlier copy left behind,
// or dest would go on holding something the list no longer names.
func TestCopyDropsEntriesRemovedFromTheList(t *testing.T) {
	home := t.TempDir()
	dest := filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	write(t, filepath.Join(home, ".claude", "settings.json"), "{}")
	write(t, filepath.Join(home, ".gitconfig"), "[user]\n")

	if err := (&config.Config{Profile: []string{".claude", ".gitconfig"}}).Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := Copy(dest); err != nil {
		t.Fatal(err)
	}
	if err := (&config.Config{Profile: []string{".gitconfig"}}).Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := Copy(dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, ".claude")); !os.IsNotExist(err) {
		t.Error(".claude was dropped from the list but its copy is still there")
	}
	if _, err := os.Stat(filepath.Join(dest, ".gitconfig")); err != nil {
		t.Error(".gitconfig is still listed and should still be there")
	}
}

// TestCopyKeepsSiblingsUnderAScharedTopLevelDirectory covers two default
// entries that share a top segment, such as the LOCALAPPDATA and APPDATA
// entries both living under AppData: dropping one must not disturb the
// other, so pruning has to walk the shared prefix rather than clearing it
// whole.
func TestCopyKeepsSiblingsUnderASharedTopLevelDirectory(t *testing.T) {
	home := t.TempDir()
	dest := filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	write(t, filepath.Join(home, "AppData", "Local", "one", "f"), "one")
	write(t, filepath.Join(home, "AppData", "Roaming", "two", "f"), "two")

	both := []string{"AppData/Local/one", "AppData/Roaming/two"}
	if err := (&config.Config{Profile: both}).Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := Copy(dest); err != nil {
		t.Fatal(err)
	}

	if err := (&config.Config{Profile: []string{"AppData/Roaming/two"}}).Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := Copy(dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "AppData", "Local", "one")); !os.IsNotExist(err) {
		t.Error("the dropped sibling is still there")
	}
	if got := read(t, filepath.Join(dest, "AppData", "Roaming", "two", "f")); got != "two" {
		t.Errorf("the remaining sibling was disturbed: %q", got)
	}
}

// TestCopyRefusesADestinationItWasNotGiven guards the sharp edge: filling a
// profile starts by clearing it of what the list no longer names, so a
// mistaken argument is not a copy into the wrong place but a deletion of one.
func TestCopyRefusesADestinationItWasNotGiven(t *testing.T) {
	for _, dest := range []string{"", ".", "profile"} {
		if _, err := Copy(dest); err == nil {
			t.Errorf("a profile at %q was accepted, and clearing it would have run", dest)
		}
	}
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Copy(file); err == nil {
		t.Error("a file was accepted as a profile to fill")
	}
	missing := filepath.Join(t.TempDir(), "never-made")
	if _, err := Copy(missing); err == nil {
		t.Error("a directory that does not exist was accepted as a profile to fill")
	}
}
