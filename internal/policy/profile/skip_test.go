package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// TestASecondRunLeavesAnUnchangedFileAlone is the skip itself, with the
// destination's timestamps made absurd on purpose: 2001 is a value no run
// could have written and exactly what the old rule refused to trust, so a
// copy that still happened would move the stamp and fail the test. The
// third fill is what proves a skipped file carries its fingerprint forward
// -- without that, the run after a quiet one would recopy everything.
func TestASecondRunLeavesAnUnchangedFileAlone(t *testing.T) {
	home, dest := useProfile(t, []string{"creds.json"})
	write(t, filepath.Join(home, "creds.json"), "token")
	dst := filepath.Join(dest, "creds.json")

	fill(t, dest)
	stale := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(dst, stale, stale); err != nil {
		t.Fatal(err)
	}

	fill(t, dest)
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(stale) {
		t.Errorf("an unchanged file was recopied, and its stamp moved to %v", info.ModTime())
	}
	if got := read(t, dst); got != "token" {
		t.Errorf("the copy holds %q", got)
	}

	fill(t, dest)
	info, err = os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(stale) {
		t.Errorf("the fingerprint was not carried forward: the third run recopied, to %v", info.ModTime())
	}
	if got := read(t, dst); got != "token" {
		t.Errorf("the copy holds %q", got)
	}
}

// TestAChangedSourceIsCopiedAgain is the ordinary half of the skip: a source
// that changed has to reach the profile, or the skip would freeze a stale
// copy in every sandbox forever.
func TestAChangedSourceIsCopiedAgain(t *testing.T) {
	home, dest := useProfile(t, []string{"creds.json"})
	write(t, filepath.Join(home, "creds.json"), "token")
	dst := filepath.Join(dest, "creds.json")

	fill(t, dest)
	write(t, filepath.Join(home, "creds.json"), "longer token")
	fill(t, dest)

	if got := read(t, dst); got != "longer token" {
		t.Errorf("the changed source never arrived: %q", got)
	}
}

// TestASameSizeSourceEditIsStillCopiedAgain is the case a size-only check
// would miss: same size, different bytes. The source's stamp is set
// explicitly so the modification-time half of the comparison moves
// deterministically rather than trusting the clock's granularity.
func TestASameSizeSourceEditIsStillCopiedAgain(t *testing.T) {
	home, dest := useProfile(t, []string{"creds.json"})
	write(t, filepath.Join(home, "creds.json"), "AAAA")
	dst := filepath.Join(dest, "creds.json")

	fill(t, dest)
	write(t, filepath.Join(home, "creds.json"), "BBBB")
	later := time.Date(2020, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(home, "creds.json"), later, later); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)

	if got := read(t, dst); got != "BBBB" {
		t.Errorf("a same-size edit was skipped as though it had not happened: %q", got)
	}
}

// TestADeletedCopyComesBackOnTheNextRun is the ordinary case the destination
// check exists for: the test stands in for the sandbox and removes its copy.
// The source has not changed, but the copy is gone, and the next run owes it
// back.
func TestADeletedCopyComesBackOnTheNextRun(t *testing.T) {
	home, dest := useProfile(t, []string{"creds.json"})
	write(t, filepath.Join(home, "creds.json"), "token")
	dst := filepath.Join(dest, "creds.json")

	fill(t, dest)
	if err := os.Remove(dst); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)

	if got := read(t, dst); got != "token" {
		t.Errorf("the deleted copy was not restored: %q", got)
	}
}

// TestATruncatedCopyComesBackOnTheNextRun is the deleted copy's neighbor: a
// zeroed file sits where the copy belongs and is not the copy, so it has to
// be rewritten rather than skipped.
func TestATruncatedCopyComesBackOnTheNextRun(t *testing.T) {
	home, dest := useProfile(t, []string{"creds.json"})
	write(t, filepath.Join(home, "creds.json"), "token")
	dst := filepath.Join(dest, "creds.json")

	fill(t, dest)
	if err := os.WriteFile(dst, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)

	if got := read(t, dst); got != "token" {
		t.Errorf("the truncated copy was not restored: %q", got)
	}
}

// TestTheCeilingStillCountsWhatItSkips is the budget rule under the skip.
// The ceiling measures what the rules file names, not what one run moved,
// and the second call here is the run most likely to be got wrong: every
// file matches, nothing is carried, and the refusal still has to happen --
// otherwise a list that grew past the ceiling would pass on exactly the
// runs that noticed.
func TestTheCeilingStillCountsWhatItSkips(t *testing.T) {
	home, dest := useProfile(t, []string{"big"})
	write(t, filepath.Join(home, "big", "one.txt"), strings.Repeat("x", 40))
	write(t, filepath.Join(home, "big", "two.txt"), strings.Repeat("x", 40))

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	entries := []config.Entry{{Path: "big"}}
	_, prints, err := copyEntries(home, root, entries, nil, 1000, nil)
	if err != nil {
		t.Fatalf("a copy under its budget was refused: %v", err)
	}
	if len(prints) != 2 {
		t.Fatalf("the first run recorded %d fingerprints, want 2 so the next run really could skip both", len(prints))
	}

	// Nothing at all has changed, every file qualifies to be skipped, and
	// 80 bytes of list against 50 of budget is still a refusal.
	if _, _, err := copyEntries(home, root, entries, nil, 50, prints); err == nil {
		t.Error("a list over its budget was allowed through because every file matched")
	}
}

// TestAnEntryRespelledBetweenRunsLeavesTheSandboxesCopyAlone is the
// respelling half of the skip: renaming an entry in the rules file --
// "agent" to "./agent" -- says nothing about the source, and a run that
// treats the new spelling as a new name deletes the copy and rebuilds it
// from the source, losing what the sandbox wrote into its own copy and
// paying for the copy again. Measured, before the key was cleaned: exactly
// that.
func TestAnEntryRespelledBetweenRunsLeavesTheSandboxesCopyAlone(t *testing.T) {
	home, dest := useProfile(t, []string{"agent"})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)
	dst := filepath.Join(dest, "agent", "auth.json")

	fill(t, dest)

	// The sandbox edits its own copy -- the same size, so the skip still
	// applies; a different size is a copy that has to be rebuilt whatever
	// the spelling says. Then a stamp no run could have written, the same
	// probe TestASecondRunLeavesAnUnchangedFileAlone uses.
	write(t, dst, `{"token":"fake"}`)
	stale := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(dst, stale, stale); err != nil {
		t.Fatal(err)
	}

	// The same entry, respelled. The source has not changed, so nothing in
	// the profile should move.
	if err := (&config.Config{Profile: config.Entries([]string{"./agent"})}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)

	if got := read(t, dst); got != `{"token":"fake"}` {
		t.Errorf("respelling the entry rebuilt the copy from the source and lost what the sandbox wrote: %q", got)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(stale) {
		t.Errorf("an unchanged source was recopied over a respelling, and the stamp moved to %v", info.ModTime())
	}
}
