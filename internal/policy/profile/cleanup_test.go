package profile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// useCleanup is useProfile plus a cleanup section, for tests about the
// cleanup: list rather than the profile: one.
func useCleanup(t *testing.T, profile []string, cleanup []string) (home, dest string) {
	t.Helper()
	home = t.TempDir()
	dest = filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	rules := &config.Config{Profile: config.Entries(profile), Cleanup: config.Masks(cleanup)}
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}
	return home, dest
}

// TestCleanupClearsAMatchingFile checks glob 1 of the design: a glob names a
// file already sitting in the sandbox's own profile, and a fill takes it
// away. Fails without the cleanup wiring, since nothing else in Copy ever
// looks at rules.Cleanup.
func TestCleanupClearsAMatchingFile(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"**/*.log"})
	write(t, filepath.Join(dest, "agent.log"), "stale output")

	fill(t, dest)

	if _, err := os.Stat(filepath.Join(dest, "agent.log")); !os.IsNotExist(err) {
		t.Errorf("agent.log matched **/*.log and should have been cleared, stat error: %v", err)
	}
}

// TestCleanupClearsAMatchingDirectoryWhole checks glob 2: a glob names a
// directory, and the whole directory goes, not merely what happens to be
// directly in it.
func TestCleanupClearsAMatchingDirectoryWhole(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{".codex/sessions/**"})
	write(t, filepath.Join(dest, ".codex", "sessions", "one", "two.json"), "session data")

	fill(t, dest)

	if _, err := os.Stat(filepath.Join(dest, ".codex", "sessions")); !os.IsNotExist(err) {
		t.Errorf(".codex/sessions matched sessions/** and should have been removed whole, stat error: %v", err)
	}
}

// TestCleanupGlobThatMatchesNothingIsNotAnError checks glob 3: a cleanup
// section naming something that is not there costs nothing but a look, and
// must not fail the run or disturb what is there.
func TestCleanupGlobThatMatchesNothingIsNotAnError(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"nothing/here/**"})
	write(t, filepath.Join(dest, "keep.txt"), "still here")

	fill(t, dest)

	if got := read(t, filepath.Join(dest, "keep.txt")); got != "still here" {
		t.Errorf("an unrelated file was disturbed by a glob matching nothing: %q", got)
	}
}

// TestCleanupRunsBeforeTheCopy checks glob 4, and the ordering the design
// insists on: cleanup naming a path the profile section then copies must
// leave the freshly copied file in place, not a hole where cleanup ran last.
// If cleanup ran after the copy instead of before it, this file would end up
// missing.
func TestCleanupRunsBeforeTheCopy(t *testing.T) {
	home, dest := useCleanup(t, []string{".claude"}, []string{".claude/settings.json"})
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"fresh":true}`)
	write(t, filepath.Join(dest, ".claude", "settings.json"), `{"stale":true}`)

	fill(t, dest)

	if got := read(t, filepath.Join(dest, ".claude", "settings.json")); got != `{"fresh":true}` {
		t.Errorf("settings.json came back as %q, want the freshly copied file, not a hole cleanup left behind", got)
	}
}

// TestCleanupTouchesNothingOutsideItsGlobs checks glob 5: a file the sandbox
// wrote that no cleanup glob names must survive a fill untouched, the same
// guarantee TestCopyLeavesTheProfilesOwnBelongingsAlone gives the profile
// section.
func TestCleanupTouchesNothingOutsideItsGlobs(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"*.log"})
	write(t, filepath.Join(dest, "keep.json"), "the sandbox's own work")

	fill(t, dest)

	if got := read(t, filepath.Join(dest, "keep.json")); got != "the sandbox's own work" {
		t.Errorf("a file no glob named was disturbed: %q", got)
	}
}

// TestCleanupRefusesAGlobThatWouldMatchTheRegistryHive checks glob 6: NTUSER.DAT
// is the sandbox's HKEY_CURRENT_USER, and a glob broad enough to reach it must
// stop the whole run rather than clear everything else and skip that one name.
func TestCleanupRefusesAGlobThatWouldMatchTheRegistryHive(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"NTUSER*"})
	write(t, filepath.Join(dest, "NTUSER.DAT"), "the hive")
	write(t, filepath.Join(dest, "keep.txt"), "should not be reached either")

	_, _, err := Copy(dest, nil, nil)
	if err == nil {
		t.Fatal("a glob that would match NTUSER.DAT was accepted")
	}
	if exit.Of(err) != exit.BadConfig {
		t.Errorf("the refusal carried exit code %v, want %v (bad-config)", exit.Of(err), exit.BadConfig)
	}
	if _, err := os.Stat(filepath.Join(dest, "NTUSER.DAT")); err != nil {
		t.Errorf("the hive is gone even though the run was refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "keep.txt")); err != nil {
		t.Errorf("cleanup cleared other files before refusing the run entirely: %v", err)
	}
}

// TestCleanupRefusesADoubleStarOnItsOwn checks glob 7: ** on its own matches
// NTUSER.DAT as surely as a glob that names it, and has to be refused for the
// same reason -- not silently cleared around.
func TestCleanupRefusesADoubleStarOnItsOwn(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"**"})
	write(t, filepath.Join(dest, "NTUSER.DAT"), "the hive")

	_, _, err := Copy(dest, nil, nil)
	if err == nil {
		t.Fatal("cleanup: [**] was accepted")
	}
	if _, err := os.Stat(filepath.Join(dest, "NTUSER.DAT")); err != nil {
		t.Errorf("the hive is gone even though the run was refused: %v", err)
	}
}

// TestEmptyCleanupChangesNothingAndCostsNoWalk checks glob 8, both halves.
// "Changes nothing" is shown against real files, filled through Copy.
// "Costs no walk" needs a sharper probe than watching files stay put: an
// inert walk over zero globs would leave every file alone too, so it would
// not tell the two apart. A nil *os.Root does: any attempt to use it panics,
// so calling clearCleanup with nil and an empty list only returns cleanly if
// the empty list is answered before root is ever touched.
func TestEmptyCleanupChangesNothingAndCostsNoWalk(t *testing.T) {
	_, dest := useCleanup(t, nil, nil)
	write(t, filepath.Join(dest, "keep.txt"), "untouched")

	fill(t, dest)

	if got := read(t, filepath.Join(dest, "keep.txt")); got != "untouched" {
		t.Errorf("keep.txt came back as %q with no cleanup globs at all", got)
	}

	removed, err := clearCleanup(nil, nil)
	if err != nil {
		t.Fatalf("an empty cleanup list returned an error instead of skipping the walk: %v", err)
	}
	if removed != nil {
		t.Errorf("an empty cleanup list reported removing %v", removed)
	}
}

// TestCleanupCannotReachOutOfTheProfileThroughAJunction checks glob 9,
// following the shape of TestCopyCannotBeWalkedOutOfTheProfileThroughAJunction.
// The glob is a name-only mask with no separator, "*.txt" -- it does not match
// "linked" itself, so clearing it can only happen by the walk descending into
// the junction and finding something inside that matches. If it followed the
// link, it would find "precious.txt" on the far side and take it, which is
// exactly the escape the root exists to make impossible.
func TestCleanupCannotReachOutOfTheProfileThroughAJunction(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"*.txt"})
	if err := os.MkdirAll(filepath.Join(dest, "linked"), 0o755); err != nil {
		t.Fatal(err)
	}

	outside := t.TempDir()
	precious := filepath.Join(outside, "precious.txt")
	write(t, precious, "do not touch")

	link := filepath.Join(dest, "linked")
	if err := os.RemoveAll(link); err != nil {
		t.Fatal(err)
	}
	junctionTo(t, link, outside)

	fill(t, dest)

	if _, err := os.Stat(precious); err != nil {
		t.Errorf("a file outside the profile was deleted through the junction: %v", err)
	}
}
