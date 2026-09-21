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

// TestAnEntryRespelledBetweenSigmasFollowsWhatTheVolumeCallsOnePlace is
// the respelling question FoldedEntryPath was built for -- "agent" to
// "./agent" -- asked with capitals instead of separators, and it is the
// volume that answers it rather than this test.
//
// Where the volume opens U+03A3 and U+03C2 onto one directory, respelling
// the entry between them says nothing about where it lands: the copy is
// still the copy, the record still vouches for it, and strings.ToLower --
// which holds the two runes apart -- would have read the recorded name as
// one the list no longer holds and taken the copy back. Where the volume
// holds them apart, the respelled entry names a different place, the old
// one is no longer named by anything, and taking it back is not a defect
// but the whole point of the take-back.
//
// Both were measured. This desk joins the two spellings; a GitHub runner's
// volume holds them apart, and this test asserted the first machine's
// answer on both until the second one said no.
func TestAnEntryRespelledBetweenSigmasFollowsWhatTheVolumeCallsOnePlace(t *testing.T) {
	sigma := "Σ"
	final := "ς"

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

	// The same spelling question, put to the rules file.
	if err := (&config.Config{Profile: config.Entries([]string{final + "ettings"})}).Save(); err != nil {
		t.Fatal(err)
	}
	copied = fill(t, dest)

	held, err := os.Stat(filepath.Join(dest, sigma+"ettings", "auth.json"))
	if !fileSystemJoins(t, sigma+"ettings.probe", final+"ettings.probe") {
		// Two places on this volume, so the list stopped naming the copied
		// one, and the take-back is right to have reached it.
		if err == nil {
			t.Errorf("the entry was respelled to a place this volume holds apart from the copied one, "+
				"so nothing names the copy any more and it should have been taken back: %v", held.Name())
		}
		if len(copied) != 0 {
			t.Errorf("the record came back as %v, vouching for a place this volume says was never copied", copied)
		}
		return
	}
	// One place on this volume: the respelling moved nothing.
	if err != nil {
		t.Errorf("respelling the entry deleted the copy its source could no longer restore: %v", err)
	}
	if len(copied) != 1 || copied[0].Path != final+"ettings" {
		t.Errorf("the record came back as %v, and nothing vouches for the copy under the new spelling", copied)
	}
}

// TestARecordNeverClaimsAPlaceTheVolumeHoldsApart is the defect the fold
// under FoldedEntryPath could not see: i and U+0131, dotless i, fold to the
// same key, and this volume holds them apart as two different directories.
// One run copies i; the source goes; the rules file respells the entry with
// U+0131 and the sandbox has made that place its own, with a file of its
// own in it. A fold that cannot tell the two places apart answers the
// record's question -- was this path copied by an earlier run? -- with the
// one place it knows, and the record claims a copy this machine never
// made. The next Clear then takes the sandbox's own file, while the
// credentials under i sit there with nothing left naming them.
//
// Where the volume joins the two spellings the defect cannot arise -- the
// respelled entry IS the copied place -- and the test says so and skips.
func TestARecordNeverClaimsAPlaceTheVolumeHoldsApart(t *testing.T) {
	dotless := "\u0131"
	if fileSystemJoins(t, "i", dotless) {
		t.Skipf("this volume opens i and %s onto one place, so the record cannot mistake one for the other", dotless)
	}

	home, dest := useProfile(t, []string{"i"})
	write(t, filepath.Join(home, "i", "auth.json"), `{"token":"real"}`)

	copied := fill(t, dest)
	if len(copied) != 1 {
		t.Fatalf("nothing was copied in the first place, so this test proves nothing: %v", copied)
	}

	// The source goes the way sources do, and the sandbox makes the place
	// the rules file is about to name its own.
	if err := os.RemoveAll(filepath.Join(home, "i")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dest, dotless, "session.txt"), "the sandbox's own session")

	if err := (&config.Config{Profile: config.Entries([]string{dotless})}).Save(); err != nil {
		t.Fatal(err)
	}
	copied = fill(t, dest)

	if len(copied) != 0 {
		t.Errorf("the record came back as %v, and %s is a place this machine never copied", pathsOf(copied), dotless)
	}
	if _, err := os.Stat(filepath.Join(dest, "i")); !os.IsNotExist(err) {
		t.Errorf("the list no longer names i, and the copy it holds stayed behind: %v", err)
	}

	if err := Clear(dest, copied); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dest, dotless, "session.txt")); err != nil {
		t.Errorf("the sandbox's own file was taken for a copy that was never made: %v", err)
	} else if string(data) != "the sandbox's own session" {
		t.Errorf("the sandbox's own file was disturbed: %q", data)
	}
}

// TestTheTakeBackReachesAPlaceTheListRenamedToAPlaceTheVolumeHoldsApart is
// the one-sided half of the same defect: the respelled place does not exist
// on disk at all, so nothing can be opened and compared, and the recorded
// copy under the old name is a stray the list no longer names. The
// take-back has to reach it anyway, or the credentials it holds sit in the
// sandbox for good with nothing left naming them -- the kept half of the
// loss the fold produced when it claimed the respelled place instead.
func TestTheTakeBackReachesAPlaceTheListRenamedToAPlaceTheVolumeHoldsApart(t *testing.T) {
	dotless := "\u0131"
	if fileSystemJoins(t, "i", dotless) {
		t.Skipf("this volume opens i and %s onto one place, so the list never stopped naming the copy", dotless)
	}

	home, dest := useProfile(t, []string{"i"})
	write(t, filepath.Join(home, "i", "auth.json"), `{"token":"real"}`)

	copied := fill(t, dest)
	if len(copied) != 1 {
		t.Fatalf("nothing was copied in the first place, so this test proves nothing: %v", copied)
	}
	if err := os.RemoveAll(filepath.Join(home, "i")); err != nil {
		t.Fatal(err)
	}

	if err := (&config.Config{Profile: config.Entries([]string{dotless})}).Save(); err != nil {
		t.Fatal(err)
	}
	copied = fill(t, dest)

	if _, err := os.Stat(filepath.Join(dest, "i", "auth.json")); !os.IsNotExist(err) {
		t.Fatalf("the list renamed the entry to a place this volume holds apart, and the copy under the old name stayed: %v", err)
	}
	if len(copied) != 0 {
		t.Errorf("the record came back as %v, and nothing this machine copied is left to vouch for", pathsOf(copied))
	}
}

// TestAnEntryRespelledOnlyInCapitalsKeepsItsCopyWhenTheSourceHasGone is the
// case respelling the ownership comparison has to keep joining, and the
// reason its case half is the file system's and not a fold's: the volume
// opens either capitals onto the one directory, and opening both spellings
// says so exactly where a fold would only guess. The record must follow the
// place and not the spelling, or forget reads the recorded entry as a name
// the list no longer holds and deletes the copy its vanished source can
// never put back.
func TestAnEntryRespelledOnlyInCapitalsKeepsItsCopyWhenTheSourceHasGone(t *testing.T) {
	if !fileSystemJoins(t, "i", "I") {
		t.Skipf("this volume holds i and I apart, which no Windows volume is expected to do")
	}

	home, dest := useProfile(t, []string{"i"})
	write(t, filepath.Join(home, "i", "auth.json"), `{"token":"real"}`)

	copied := fill(t, dest)
	if len(copied) != 1 {
		t.Fatalf("nothing was copied in the first place, so this test proves nothing: %v", copied)
	}
	if err := os.RemoveAll(filepath.Join(home, "i")); err != nil {
		t.Fatal(err)
	}

	if err := (&config.Config{Profile: config.Entries([]string{"I"})}).Save(); err != nil {
		t.Fatal(err)
	}
	copied = fill(t, dest)

	if _, err := os.Stat(filepath.Join(dest, "i", "auth.json")); err != nil {
		t.Errorf("respelling the entry in capitals deleted the copy its source could no longer restore: %v", err)
	}
	if len(copied) != 1 || copied[0].Path != "I" {
		t.Errorf("the record came back as %v, and nothing left vouches for the copy that survived", copied)
	}
}

func TestDedupeEntriesUsesTheVolumeForDistinctUnicodeNames(t *testing.T) {
	dotless := "\u0131"
	dest := t.TempDir()
	if fileSystemJoins(t, "i", dotless) {
		t.Skipf("this volume opens i and %s onto one place", dotless)
	}
	if err := os.MkdirAll(filepath.Join(dest, "i"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dest, dotless), 0o755); err != nil {
		t.Fatal(err)
	}

	got := DedupeEntries(dest, []config.Entry{{Path: "i"}, {Path: dotless}})
	if len(got) != 2 {
		t.Fatalf("record merged distinct volume paths: %v", pathsOf(got))
	}
}

func TestDedupeEntriesMergesCapitalRespellingsOnTheVolume(t *testing.T) {
	if !fileSystemJoins(t, "i", "I") {
		t.Skip("this volume keeps i and I apart")
	}
	dest := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dest, "i"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := DedupeEntries(dest, []config.Entry{{Path: "i"}, {Path: "I"}})
	if len(got) != 1 {
		t.Fatalf("record kept two spellings of one volume path: %v", pathsOf(got))
	}
}

func TestDedupeEntriesKeepsDistinctHardLinkNames(t *testing.T) {
	dest := t.TempDir()
	first := filepath.Join(dest, "first")
	second := filepath.Join(dest, "second")
	if err := os.WriteFile(first, []byte("same inode"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, second); err != nil {
		t.Skipf("hard links unavailable on this volume: %v", err)
	}
	got := DedupeEntries(dest, []config.Entry{{Path: "first"}, {Path: "second"}})
	if len(got) != 2 {
		t.Fatalf("record merged two names of one hard-linked file: %v", pathsOf(got))
	}
}

// TestHardLinkNamesStaySeparateWhenOneIsRespelt checks the directory-entry
// lookup path. A case-only alternate spelling is resolved by Windows to the
// exact stored entry, even when another hard-link name shares its inode.
// Dedupe must keep both records, and Clear must then remove both names
// explicitly.
func TestHardLinkNamesStaySeparateWhenOneIsRespelt(t *testing.T) {
	dest := t.TempDir()
	first := filepath.Join(dest, "first")
	second := filepath.Join(dest, "second")
	if err := os.WriteFile(first, []byte("same inode"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, second); err != nil {
		t.Skipf("hard links unavailable on this volume: %v", err)
	}

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if !recordVouches(newPlaceResolver(root), []string{"first"}, "FIRST") {
		t.Fatal("a case-only spelling of the recorded directory entry lost its proof")
	}
	if recordVouches(newPlaceResolver(root), []string{"first"}, "SECOND") {
		t.Fatal("a different hard-link name was treated as the recorded entry")
	}

	entries := DedupeEntries(dest, []config.Entry{{Path: "FIRST"}, {Path: "SECOND"}})
	if len(entries) != 2 {
		t.Fatalf("dedupe merged ambiguous hard-link names: %v", pathsOf(entries))
	}
	if err := Clear(dest, entries); err != nil {
		t.Fatal(err)
	}
	if left, err := os.ReadDir(dest); err != nil {
		t.Fatal(err)
	} else if len(left) != 0 {
		t.Errorf("clear left hard-link directory entries behind: %v", left)
	}
}

// TestCopyKeepsAnExactRecordThroughARespellingAndHardLink checks the full
// record lifecycle. The source vanishes after the first copy, while the
// sandbox has made another hard-link name for the destination. A case-only
// respelling must still vouch for the exact recorded directory entry, and
// Clear must remove that entry without guessing at the other name.
func TestCopyKeepsAnExactRecordThroughARespellingAndHardLink(t *testing.T) {
	home, dest := useProfile(t, []string{"first"})
	write(t, filepath.Join(home, "first"), "copied")

	copied := fill(t, dest)
	if len(copied) != 1 {
		t.Fatalf("nothing was copied in the first place, so this proves nothing: %v", copied)
	}
	if err := os.Link(filepath.Join(dest, "first"), filepath.Join(dest, "second")); err != nil {
		t.Skipf("hard links unavailable on this volume: %v", err)
	}
	if err := os.Remove(filepath.Join(home, "first")); err != nil {
		t.Fatal(err)
	}
	if err := (&config.Config{Profile: config.Entries([]string{"FIRST"})}).Save(); err != nil {
		t.Fatal(err)
	}

	copied = fill(t, dest)
	if len(copied) != 1 || copied[0].Path != "FIRST" {
		t.Fatalf("the vanished source lost its exact record through the hard link: %v", copied)
	}
	if _, err := os.Stat(filepath.Join(dest, "first")); err != nil {
		t.Fatalf("the surviving copy was not retained: %v", err)
	}

	if err := Clear(dest, copied); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "first")); !os.IsNotExist(err) {
		t.Errorf("Clear did not remove the recorded directory entry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "second")); err != nil {
		t.Errorf("Clear removed the sandbox's other hard-link name: %v", err)
	}
}
