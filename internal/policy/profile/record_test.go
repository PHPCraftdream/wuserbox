package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// TestCopySkipsMissingEntriesWithoutError: a source that is not on this
// machine is not an error, and nothing is copied for it. With no earlier
// record naming it, the entry does not go on the record either -- a record
// is a claim about copies this tool made, and claiming a path that was
// never copied from anywhere claims whatever the sandbox itself put there,
// which the next --no-ai would take back with the rest. The entry stays on
// the record only where the record before this run already named it, which
// TestACopyWhoseSourceHasGoneStaysOnTheRecordToClear holds.
func TestCopySkipsMissingEntriesWithoutError(t *testing.T) {
	home, dest := useProfile(t, []string{".claude", ".codex"})
	write(t, filepath.Join(home, ".claude", "settings.json"), "{}")

	copied := fill(t, dest)
	if !reflect.DeepEqual(pathsOf(copied), []string{".claude"}) {
		t.Errorf("reported %v, and .codex has never been copied from anywhere", copied)
	}
	if _, err := os.Stat(filepath.Join(dest, ".codex")); err == nil {
		t.Error("a name that does not exist on this machine was copied anyway")
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

	if err := (&config.Config{Profile: config.Entries([]string{".claude", ".gitconfig"})}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)
	if err := (&config.Config{Profile: config.Entries([]string{".gitconfig"})}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)
	if _, err := os.Stat(filepath.Join(dest, ".claude")); !os.IsNotExist(err) {
		t.Error(".claude was dropped from the list but its copy is still there")
	}
	if _, err := os.Stat(filepath.Join(dest, ".gitconfig")); err != nil {
		t.Error(".gitconfig is still listed and should still be there")
	}
}

// TestACopyWhoseSourceHasGoneStaysOnTheRecordToClear is the one path that
// never reached the write-down-before-copying rule: copyEntries asks after
// the source before it gets there, and a source that is not on this machine
// was skipped without its entry ever being appended. A run that otherwise
// succeeded then wrote a record without it, and the copy already sitting in
// the sandbox's profile -- auth.json, say, with the source deleted since --
// belonged to nobody: the next --no-ai reported success while the stale
// credentials stayed inside the sandbox for good.
func TestACopyWhoseSourceHasGoneStaysOnTheRecordToClear(t *testing.T) {
	home, dest := useProfile(t, []string{".codex/auth.json"})
	auth := filepath.Join(home, ".codex", "auth.json")
	write(t, auth, `{"token":"real"}`)

	copied := fill(t, dest)
	if len(copied) != 1 {
		t.Fatalf("nothing was copied in the first place, so this test proves nothing: %v", copied)
	}
	if err := os.Remove(auth); err != nil {
		t.Fatal(err)
	}

	// The next run: the source is gone, everything else about the run
	// succeeds, and the record it leaves behind is all a later --no-ai has.
	copied = fill(t, dest)

	if err := Clear(dest, copied); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, ".codex", "auth.json")); !os.IsNotExist(err) {
		t.Error("the copy outlived its source and the record both, and nothing left will ever take it back")
	}
}

// TestARecordClaimsOnlyWhatAnEarlierRunCopied is the guard on the difference
// os.Stat cannot see. A source that has gone since an earlier run copied it
// and a source that was never here look identical to that call and are
// opposite in what the record may claim: the first leaves a copy sitting in
// the sandbox that the record is the only thing able to vouch for, while the
// second names a path this machine never had -- local-agent was never under
// the user's profile, the agent inside the sandbox wrote its own session
// under that name, and a record claiming local-agent handed the next --no-ai
// an instruction to delete the sandbox's own file.
func TestARecordClaimsOnlyWhatAnEarlierRunCopied(t *testing.T) {
	home, dest := useProfile(t, []string{"local-agent", ".codex/auth.json"})
	write(t, filepath.Join(home, ".codex", "auth.json"), `{"token":"real"}`)
	write(t, filepath.Join(dest, "local-agent", "session.txt"), "the sandbox's own session")

	copied := fill(t, dest)
	if !reflect.DeepEqual(pathsOf(copied), []string{".codex/auth.json"}) {
		t.Errorf("the record came back as %v, and local-agent was never copied from anywhere", copied)
	}

	// The source goes the way sources do. The next run still has to vouch
	// for the copy it already put in the sandbox, or nothing left will ever
	// take that copy back.
	if err := os.Remove(filepath.Join(home, ".codex", "auth.json")); err != nil {
		t.Fatal(err)
	}
	copied = fill(t, dest)
	if !reflect.DeepEqual(pathsOf(copied), []string{".codex/auth.json"}) {
		t.Fatalf("the record came back as %v, want exactly the entry whose source has gone", copied)
	}

	if err := Clear(dest, copied); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, ".codex", "auth.json")); !os.IsNotExist(err) {
		t.Error("the copy outlived its source and stayed in the sandbox's profile")
	}
	if data, err := os.ReadFile(filepath.Join(dest, "local-agent", "session.txt")); err != nil {
		t.Errorf("the sandbox's own file was taken back with a copy that was never made: %v", err)
	} else if string(data) != "the sandbox's own session" {
		t.Errorf("the sandbox's own file was disturbed: %q", data)
	}
}

// TestAnEntryRespelledBetweenRunsKeepsItsCopyWhenTheSourceHasGone is the
// respelling half of the record's vouching: the rules file can rename an
// entry without renaming the place it lands -- "agent" respelled "./agent"
// -- and both spellings land on the same place inside the profile, so the
// record has to follow the place and not the spelling. Measured, before the
// key was cleaned: forget built its keep set from the new spelling, read the
// recorded "agent" as a name the list no longer held, and clearEntry deleted
// the copy; copyEntries could not restore it because the source had gone --
// a drive not mounted, a tool uninstalled -- and the run reported success.
func TestAnEntryRespelledBetweenRunsKeepsItsCopyWhenTheSourceHasGone(t *testing.T) {
	home, dest := useProfile(t, []string{"agent"})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)

	copied := fill(t, dest)
	if len(copied) != 1 {
		t.Fatalf("nothing was copied in the first place, so this test proves nothing: %v", copied)
	}

	// The source goes the way sources do: temporarily, as these things
	// usually are.
	if err := os.RemoveAll(filepath.Join(home, "agent")); err != nil {
		t.Fatal(err)
	}

	// The same entry, respelled. within lands both spellings on agent, and
	// the key forget and the record fold by has to agree with within or the
	// copy reads as orphaned.
	if err := (&config.Config{Profile: config.Entries([]string{"./agent"})}).Save(); err != nil {
		t.Fatal(err)
	}
	copied = fill(t, dest)

	if _, err := os.Stat(filepath.Join(dest, "agent", "auth.json")); err != nil {
		t.Errorf("respelling the entry deleted the copy its source could no longer restore: %v", err)
	}
	if !reflect.DeepEqual(pathsOf(copied), []string{"./agent"}) {
		t.Errorf("the record came back as %v, and nothing left vouches for the copy that survived", copied)
	}

	// And the record still vouches: the take-back a later --no-ai runs has
	// to reach the copy by the new spelling too.
	if err := Clear(dest, copied); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "agent", "auth.json")); !os.IsNotExist(err) {
		t.Error("the copy outlived its source and the record both, and nothing left will ever take it back")
	}
}

// TestAnEntryRespelledBetweenSigmasKeepsItsCopyWhenTheSourceHasGone is the
// respelling defect FoldedEntryPath was built for -- "agent" to "./agent" --
// again, with capitals strings.ToLower cannot join: Σ and ς are different
// runes to ToLower, but the file system equates the two spellings, so the
// entry never left the list, while the folded key reads the recorded one as
// a name it no longer holds and the bare take-back RemoveAll deletes the
// directory with everything the sandbox keeps under it. Same defect as the
// capitals tests, arriving through the record instead of the present list.
func TestAnEntryRespelledBetweenSigmasKeepsItsCopyWhenTheSourceHasGone(t *testing.T) {
	sigma := "\u03a3"
	final := "\u03c2"

	home, dest := useProfile(t, []string{sigma + "ettings"})
	write(t, filepath.Join(home, sigma+"ettings", "auth.json"), `{"token":"real"}`)

	copied := fill(t, dest)
	if len(copied) != 1 {
		t.Fatalf("nothing was copied in the first place, so this test proves nothing: %v", copied)
	}

	// The source goes the way sources do.
	if err := os.RemoveAll(filepath.Join(home, sigma+"ettings")); err != nil {
		t.Fatal(err)
	}

	// The same place, respelled. NTFS opens both spellings onto the same
	// directory; strings.ToLower holds them apart.
	if err := (&config.Config{Profile: config.Entries([]string{final + "ettings"})}).Save(); err != nil {
		t.Fatal(err)
	}
	copied = fill(t, dest)

	if got := read(t, filepath.Join(dest, sigma+"ettings", "auth.json")); got != `{"token":"real"}` {
		t.Errorf("respelling the entry deleted the copy its source could no longer restore: %q", got)
	}
	if len(copied) != 1 || copied[0].Path != final+"ettings" {
		t.Errorf("the record came back as %v, and nothing vouches for the copy under the new spelling", copied)
	}
}
