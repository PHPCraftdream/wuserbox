package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// TestAMissingSourceBehindALockedAncestorStopsTheCopyAndTheRecordSurvives is
// the round-11 review's combination, measured end to end through the public
// Copy: an entry whose source has gone and whose copy stands under a
// destination directory an ordinary program holds shut. The destination was
// never asked, so the answer the stretch gives -- holds false, no error --
// retired the entry from the record and reported the run a success, and the
// copy outlived its record with nothing left able to name it. The two refusal
// tests beside it pass on their own; this is the combination neither of them
// measures, and it is what fillProfile's partial-record union carries over.
func TestAMissingSourceBehindALockedAncestorStopsTheCopyAndTheRecordSurvives(t *testing.T) {
	home, dest := useProfile(t, []string{"agent/auth.json"})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)
	previously := fill(t, dest)
	if len(previously) != 1 {
		t.Fatalf("nothing was copied in the first place, so this test proves nothing: %v", previously)
	}

	// The source goes the way sources do.
	if err := os.Remove(filepath.Join(home, "agent", "auth.json")); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	release := lockExclusive(t, filepath.Join(dest, "agent"), true)
	holdProof(t, root, "agent")

	// The record names agent/auth.json, the source is gone, and the
	// directory the copy stands under cannot be asked about. The answer
	// the stretch used to give -- holds false, no error -- retired the
	// entry from the record and reported the run a success, and the copy
	// outlived its record with nothing left able to name it.
	copied, prints, err := Copy(dest, previously, lastPrints[dest])
	if err == nil {
		t.Fatal("a copy that could not ask whether the record's copy still stands retired the entry by reporting success")
	}
	if !strings.Contains(err.Error(), "auth.json") {
		t.Errorf("the refusal did not name the entry it stopped on: %v", err)
	}
	release()

	// fillProfile's partial union is what carries the record over a failed
	// run: whatever came back is unioned with what stood before, so the
	// entry survives the refusal and the next run asks again.
	survived := DedupeEntries(dest, append(append([]config.Entry{}, copied...), previously...))
	if want := []string{"agent/auth.json"}; !reflect.DeepEqual(pathsOf(survived), want) {
		t.Fatalf("the record the failed run left behind came back as %v, want %v: the entry a locked destination may still be holding was retired anyway", pathsOf(survived), want)
	}

	// The retry, once the hold lets go: the copy is witnessed where it
	// stands, the entry stays on the record, and the file was never
	// touched.
	if got := read(t, filepath.Join(dest, "agent", "auth.json")); got != `{"token":"real"}` {
		t.Fatalf("the copy behind the hold was disturbed by the run that could not ask about it: %q", got)
	}
	copied, _, err = Copy(dest, survived, prints)
	if err != nil {
		t.Fatalf("the retry after the hold let go failed: %v", err)
	}
	if !reflect.DeepEqual(pathsOf(copied), []string{"agent/auth.json"}) {
		t.Errorf("the retry's record came back as %v, want the entry whose copy still stands", pathsOf(copied))
	}

	// And the record the retry left is the one a later --no-ai needs.
	if err := Clear(dest, copied); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "agent", "auth.json")); !os.IsNotExist(err) {
		t.Error("the copy outlived its source, the record and the take-back all three")
	}
}

// TestACopyWhoseSourceAndCopyHaveBothGoneLeavesTheRecordQuietly is the
// honest-absent control: the destination really is missing, nobody holds it
// shut, and the question answered itself. A refusal here would wedge every
// run behind a copy that is simply gone, which is the other half of the
// round-11 fix the combination test stands on.
func TestACopyWhoseSourceAndCopyHaveBothGoneLeavesTheRecordQuietly(t *testing.T) {
	home, dest := useProfile(t, []string{"agent/auth.json"})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)
	previously := fill(t, dest)
	if len(previously) != 1 {
		t.Fatalf("nothing was copied in the first place, so this test proves nothing: %v", previously)
	}

	// The source goes, and the copy in the sandbox goes with it -- the
	// destination's own nothing, no hold anywhere. A refusal here would
	// wedge every run behind a copy that is simply gone.
	if err := os.Remove(filepath.Join(home, "agent", "auth.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dest, "agent", "auth.json")); err != nil {
		t.Fatal(err)
	}

	copied, _, err := Copy(dest, previously, lastPrints[dest])
	if err != nil {
		t.Fatalf("the volume's own nothing was read as a refusal: %v", err)
	}
	if len(copied) != 0 {
		t.Errorf("the record came back as %v, want it empty: the copy both lists could name is gone from the profile", pathsOf(copied))
	}
}

// TestAClearThatCannotResolveASuspiciousRecordStopsAndTheRetryTakesItBack is
// the round-12 review's neighbor path, measured through the public Clear: an
// ordinary legacy alias -- "auth.json." opens the file "auth.json" keeps,
// Win32 strips the dot -- sitting behind a hold the volume cannot answer
// through. The old answer read that as reserved, spared the entry and
// reported the clear finished, and the caller's --no-ai recorded an empty
// profile over a copy nothing had checked. The clear stops instead, with the
// known reserved hive and the ordinary copy both standing, and the retry
// spares the hive by the file it reaches while taking the copy the record
// still names.
func TestAClearThatCannotResolveASuspiciousRecordStopsAndTheRetryTakesItBack(t *testing.T) {
	dest := t.TempDir()
	hive := filepath.Join(dest, "NTUSER.DAT")
	write(t, hive, "the hive the profile service built")
	write(t, filepath.Join(dest, "auth.json"), `{"token":"real"}`)
	record := []config.Entry{
		{Path: "auth.json."},
		{Path: "NTUSER.DAT."},
	}

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	release := lockExclusive(t, filepath.Join(dest, "auth.json"), false)
	holdProof(t, root, "auth.json.")

	// The record's padded spelling opens the plain file -- Win32 strips
	// the dot -- and the hold keeps the volume from answering, so whether
	// the entry names a reserved path cannot be asked. The old answer read
	// that as reserved, spared the entry and reported the clear finished,
	// and the caller's --no-ai recorded an empty profile over a copy
	// nothing had checked. The clear stops instead, with the record
	// standing.
	if err := Clear(dest, record); err == nil {
		t.Fatal("a take-back that could not ask whether a suspicious record names a reserved path reported the clear finished")
	}
	release()
	if got := read(t, filepath.Join(dest, "auth.json")); got != `{"token":"real"}` {
		t.Fatalf("the copy behind the hold was disturbed by the clear that could not ask about it: %q", got)
	}
	if got := read(t, hive); got != "the hive the profile service built" {
		t.Errorf("the hive was disturbed by the clear that stopped before reaching it: %q", got)
	}

	// The retry, once the hold lets go: the padded spelling resolves, the
	// hive's entry is spared by the file it reaches, and the ordinary copy
	// the record still names goes at last.
	if err := Clear(dest, record); err != nil {
		t.Fatalf("the retry after the hold let go failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "auth.json")); !os.IsNotExist(err) {
		t.Errorf("the copy the record still names survived a clear nothing holds shut any more: %v", err)
	}
	if got := read(t, hive); got != "the hive the profile service built" {
		t.Errorf("the reserved hive was taken back with the ordinary copy beside it: %q", got)
	}
}

// TestATakeBackThatCannotAskASuspiciousSpellingStopsAndTheRetryFinishes pins
// the guard's third answer where it decides a deletion. A record spelling the
// hive through an alias whose path cannot be asked about -- Microsoft below
// AppData/Local is a junction pointing outside the profile, and the root
// refuses to open through a reparse point -- opens a name the volume may
// resolve onto the hive, and the question of where it lands goes unanswered:
// the open fails for a reason that is not absence. The answer this used to
// give was a spare and a reported finish: sparing the entry stood, but
// reporting the clear finished was what retired the record, and a succeeding
// Clear is exactly what lets the caller's --no-ai write an empty profile back
// over a copy nothing had checked -- the round-12 review's record wipe. The
// clear stops instead, with the hive, the record's plain-named neighbor and
// the record itself all three standing, and the retry -- once nothing holds
// the name shut any more -- takes the neighbor back and leaves the hive where
// the profile service put it.
func TestATakeBackThatCannotAskASuspiciousSpellingStopsAndTheRetryFinishes(t *testing.T) {
	_, dest := useProfile(t, []string{})
	real := filepath.Join(t.TempDir(), "elsewhere")
	hive := filepath.Join(real, "Windows", "UsrClass.dat")
	write(t, hive, profileServiceHive)
	// The junction hangs off AppData/Local -- it has to, because that is
	// where the record's spelling sends the walk: Microsoft below it is a
	// junction pointing outside the profile, and the root refuses to open
	// through a reparse point, so the open comes back "path escapes from
	// parent" rather than an answer. The control file's own write is what
	// puts the directory there for mklink to hang the junction off, and the
	// hive sits behind the link -- reachable by the plain file system calls
	// the fixture writes with, refused to the root that would have to open
	// it to answer.
	control := filepath.Join(dest, "AppData", "Local", "ours.txt")
	write(t, control, "ours")
	junctionTo(t, filepath.Join(dest, "AppData", "Local", "Microsoft"), real)
	record := []config.Entry{
		{Path: "AppData/Local/Microsoft./Windows/UsrClass.dat"},
		{Path: "AppData/Local/ours.txt"},
	}

	if err := Clear(dest, record); err == nil {
		t.Fatal("a take-back that could not ask whether a suspicious record names a reserved path reported the clear finished")
	}
	if got := read(t, hive); got != profileServiceHive {
		t.Errorf("the take-back deleted through an answer it never got: the hive now holds %q", got)
	}
	if _, err := os.Stat(control); err != nil {
		t.Errorf("the stop did not keep the record's plain-named neighbor standing: %v", err)
	}

	// The branch itself, asked directly: the spelling is suspicious, the
	// open is refused rather than answered, and the resolution says so --
	// this is the answer the stop above stands on.
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, answer, _ := resolvedRootRel(root, "AppData/Local/Microsoft./Windows/UsrClass.dat"); answer != answerUnknown {
		t.Errorf("an open refused, not answered, resolved as %v: the guard would have read that as the tables' leave to delete", answer)
	}

	// The retry, once the junction is gone: the suspicious spelling opens
	// nothing, the hive behind it is nobody's to take, and the clear
	// finishes what it started over the neighbor the record still names.
	if err := os.Remove(filepath.Join(dest, "AppData", "Local", "Microsoft")); err != nil {
		t.Fatal(err)
	}
	if err := Clear(dest, record); err != nil {
		t.Fatalf("the retry after the junction went away refused a record an earlier run of this tool wrote: %v", err)
	}
	if _, err := os.Stat(control); !os.IsNotExist(err) {
		t.Errorf("the retry spared a plain file the record names as if the hive's spelling protected it: %v", err)
	}
	if got := read(t, hive); got != profileServiceHive {
		t.Errorf("the hive outside the profile was disturbed by the retry: it now holds %q", got)
	}
}
