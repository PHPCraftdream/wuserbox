package profile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// staleStamp is the modification time no run could have written, the probe
// TestASecondRunLeavesAnUnchangedFileAlone plants: what a run copies moves
// off it, and what a run skips keeps it. Reading the stamps back after a
// real Copy is how the tests below get the run's own answer to "copied or
// skipped" -- Copy returns skips and copies carried together in one
// fingerprint map by design, so the return value cannot tell them apart,
// and the stamps are what the run did rather than a number restated by
// hand.
var staleStamp = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

// plantStaleStamps sets every regular file under root, however deep, to
// staleStamp, so that the run which follows is the only thing able to move
// one.
func plantStaleStamps(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		return os.Chtimes(path, staleStamp, staleStamp)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// whatTheRunDid counts the regular files under root by what the run that
// followed the planting did to them: a file still carrying staleStamp was
// skipped, one whose stamp moved was copied.
func whatTheRunDid(t *testing.T, root string) (copied, skipped int) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.ModTime().Equal(staleStamp) {
			skipped++
		} else {
			copied++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return copied, skipped
}

// planFor is one entry's plan, failing with the whole plan in the message
// when the entry is missing, so a failure reads what was actually
// previewed rather than a nil field.
func planFor(t *testing.T, plans []EntryPlan, path string) EntryPlan {
	t.Helper()
	for _, plan := range plans {
		if plan.Path == path {
			return plan
		}
	}
	t.Fatalf("the plan has no entry for %s: %+v", path, plans)
	return EntryPlan{}
}

// TestThePlanCountsAFileCleanupWouldClearAsACopy is the reported case. A
// file unchanged since the last run, with a fingerprint that still
// describes it, and named by a cleanup: glob, is what a real fill deletes
// and then copies back into the space the deletion left -- clearCleanup
// runs before copyEntries, and nothing the copy walks is left of the file
// the fingerprint described. Measured, before the fix: the plan answered
// "Skipped: 1, Files: 0" for this tree, because the copy half asked the
// skip question of a tree the cleanup half had never been allowed to
// touch.
//
// The plan's numbers are not restated here but read back off a real Copy
// on the same tree, by the stamps. planSink and copySink share one walk,
// so the two cannot disagree; this is the test that catches them the day
// they can.
func TestThePlanCountsAFileCleanupWouldClearAsACopy(t *testing.T) {
	home, dest := useCleanup(t, []string{"agent"}, []string{"agent/auth.json"})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)
	write(t, filepath.Join(home, "agent", "notes.txt"), "kept")

	fill(t, dest)
	plantStaleStamps(t, dest)

	cleanup, entries, err := Plan(dest, lastPrints[dest])
	if err != nil {
		t.Fatal(err)
	}
	if len(cleanup) != 1 || cleanup[0].Path != "agent/auth.json" || cleanup[0].Files != 1 {
		t.Fatalf("the plan did not name the one deletion the glob makes: %+v", cleanup)
	}
	plan := planFor(t, entries, "agent")
	if plan.Files != 1 || plan.Bytes != int64(len(`{"token":"real"}`)) {
		t.Errorf("auth.json is named by the cleanup glob, so the run deletes it and copies it again, but "+
			"the plan reported Files: %d, Bytes: %d, want the one copy and its %d bytes",
			plan.Files, plan.Bytes, len(`{"token":"real"}`))
	}
	if plan.Skipped != 1 {
		t.Errorf("notes.txt is reached by no glob and should be the one skip, got Skipped: %d", plan.Skipped)
	}

	// The real run, on the tree the plan just read: what it does to the
	// stamps is the answer the plan is compared against below.
	fill(t, dest)

	copied, skipped := whatTheRunDid(t, filepath.Join(dest, "agent"))
	if copied != 1 || skipped != 1 {
		t.Fatalf("the real run copied %d and skipped %d, want one of each -- the comparison below is meaningless otherwise", copied, skipped)
	}
	if plan.Files != copied || plan.Skipped != skipped {
		t.Errorf("the plan said Files: %d, Skipped: %d; the run did Files: %d, Skipped: %d", plan.Files, plan.Skipped, copied, skipped)
	}
}

// TestThePlanCountsEverythingUnderADirectoryTakenWholeAsACopy is the
// directory shape of the same defect. cleanDir records one plan entry for
// a directory the globs take whole, so the question the copy half has to
// ask of a destination is not "is this the removed path" but "does it sit
// at or under one": with cleanup: [agent] and profile: [agent], auth.json
// is a copy into a directory that will not exist again until the copy
// makes it, and one.json, a level below the removal, is a copy an equality
// question would have handed to the skip logic instead. Measured, before
// the fix: the plan reported both files skipped.
func TestThePlanCountsEverythingUnderADirectoryTakenWholeAsACopy(t *testing.T) {
	home, dest := useCleanup(t, []string{"agent"}, []string{"agent"})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)
	write(t, filepath.Join(home, "agent", "sessions", "one.json"), "{}")

	fill(t, dest)
	plantStaleStamps(t, dest)

	cleanup, entries, err := Plan(dest, lastPrints[dest])
	if err != nil {
		t.Fatal(err)
	}
	if len(cleanup) != 1 || cleanup[0].Path != "agent" || cleanup[0].Files != 2 {
		t.Fatalf("the plan did not name agent whole with its two files: %+v", cleanup)
	}
	plan := planFor(t, entries, "agent")
	if plan.Files != 2 || plan.Skipped != 0 {
		t.Errorf("the run takes agent/ whole and copies both files back into it, but the plan reported "+
			"Files: %d, Skipped: %d", plan.Files, plan.Skipped)
	}

	// The real run, on the tree the plan just read: what it does to the
	// stamps is the answer the plan is compared against below.
	fill(t, dest)

	copied, skipped := whatTheRunDid(t, filepath.Join(dest, "agent"))
	if copied != 2 || skipped != 0 {
		t.Fatalf("the real run copied %d and skipped %d, want both copied -- the comparison below is meaningless otherwise", copied, skipped)
	}
	if plan.Files != copied || plan.Skipped != skipped {
		t.Errorf("the plan said Files: %d, Skipped: %d; the run did Files: %d, Skipped: %d", plan.Files, plan.Skipped, copied, skipped)
	}
}

// TestThePlanStillSkipsAFileNoGlobNames is the guard on the other side: a
// file whose fingerprint still describes it, reached by no cleanup glob,
// is still a skip. A fix that answered "copy" for everything would pass
// the two tests above and cost every unchanged file its skip, which is
// most of the roughly 2.8 MB a run no longer recopies -- the reason the
// fingerprint exists.
func TestThePlanStillSkipsAFileNoGlobNames(t *testing.T) {
	home, dest := useCleanup(t, []string{"agent"}, []string{"agent/other.log"})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)

	fill(t, dest)
	plantStaleStamps(t, dest)

	cleanup, entries, err := Plan(dest, lastPrints[dest])
	if err != nil {
		t.Fatal(err)
	}
	if len(cleanup) != 0 {
		t.Fatalf("a glob matching nothing was reported as a removal: %+v", cleanup)
	}
	plan := planFor(t, entries, "agent")
	if plan.Files != 0 || plan.Bytes != 0 || plan.Skipped != 1 {
		t.Errorf("an untouched file is still a skip, got Files: %d, Bytes: %d, Skipped: %d", plan.Files, plan.Bytes, plan.Skipped)
	}

	// The real run, on the tree the plan just read: what it does to the
	// stamps is the answer the plan is compared against below.
	fill(t, dest)

	copied, skipped := whatTheRunDid(t, filepath.Join(dest, "agent"))
	if copied != 0 || skipped != 1 {
		t.Fatalf("the real run copied %d and skipped %d, want all skipped -- the comparison below is meaningless otherwise", copied, skipped)
	}
	if plan.Files != copied || plan.Skipped != skipped {
		t.Errorf("the plan said Files: %d, Skipped: %d; the run did Files: %d, Skipped: %d", plan.Files, plan.Skipped, copied, skipped)
	}
}

// TestThePlanAsksThePackageForTheSpelling is the spelling half of the same
// defect. The two sides of the comparison are written by different
// witnesses: a plan path comes out of the destination tree's own names, a
// destination path out of the rules entry and the source's, and Windows
// holds both spellings of one file at once -- the sandbox here has kept
// its copy as AUTH.JSON since the run that copied it, so the glob naming
// auth.json and the destination naming auth.json both reach AUTH.JSON,
// and the copy behind the fingerprint is a copy, not a skip. Compared by
// the bytes of one spelling the two are strangers, which is the mistake
// the package's one folded key exists to prevent.
func TestThePlanAsksThePackageForTheSpelling(t *testing.T) {
	home, dest := useCleanup(t, []string{"agent"}, []string{"agent/auth.json"})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)

	fill(t, dest)
	// Only the case moves: it stays the file the fingerprint describes and
	// the glob still names.
	if err := os.Rename(filepath.Join(dest, "agent", "auth.json"), filepath.Join(dest, "agent", "AUTH.JSON")); err != nil {
		t.Fatal(err)
	}
	plantStaleStamps(t, dest)

	_, entries, err := Plan(dest, lastPrints[dest])
	if err != nil {
		t.Fatal(err)
	}
	plan := planFor(t, entries, "agent")
	if plan.Files != 1 || plan.Bytes != int64(len(`{"token":"real"}`)) || plan.Skipped != 0 {
		t.Errorf("AUTH.JSON and auth.json are one file to Windows, so the run deletes it and copies it "+
			"back, but the plan reported Files: %d, Bytes: %d, Skipped: %d", plan.Files, plan.Bytes, plan.Skipped)
	}

	// The real run, on the tree the plan just read: what it does to the
	// stamps is the answer the plan is compared against below.
	fill(t, dest)

	copied, skipped := whatTheRunDid(t, filepath.Join(dest, "agent"))
	if copied != 1 || skipped != 0 {
		t.Fatalf("the real run copied %d and skipped %d, want the one copy -- the comparison below is meaningless otherwise", copied, skipped)
	}
	if plan.Files != copied || plan.Skipped != skipped {
		t.Errorf("the plan said Files: %d, Skipped: %d; the run did Files: %d, Skipped: %d", plan.Files, plan.Skipped, copied, skipped)
	}
}

// TestThePlanSeesADirectoryTakenWholeFromInsideAnother is the shape the
// ancestor walk was getting wrong: a cleanup glob naming a directory more
// than one segment deep. The keys the walk compares are spelled with
// forward slashes, because that is what FoldedEntryPath hands back, and
// filepath.Dir on Windows hands back the native spelling of whatever it was
// given -- so the first ancestor of agent/sessions/one.json came back as
// agent\sessions and matched nothing, while the plan went on reporting the
// skip the run does not make. A glob naming a top-level directory hid it,
// since one segment has no separator to convert, which is why the two tests
// above passed over it.
func TestThePlanSeesADirectoryTakenWholeFromInsideAnother(t *testing.T) {
	home, dest := useCleanup(t, []string{"agent"}, []string{"agent/sessions"})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)
	write(t, filepath.Join(home, "agent", "sessions", "one.json"), "session one")

	fill(t, dest)
	plantStaleStamps(t, dest)

	cleanup, entries, err := Plan(dest, lastPrints[dest])
	if err != nil {
		t.Fatal(err)
	}
	if len(cleanup) != 1 || cleanup[0].Path != "agent/sessions" {
		t.Fatalf("the plan did not name agent/sessions as the one removal: %+v", cleanup)
	}
	plan := planFor(t, entries, "agent")
	if plan.Files != 1 || plan.Skipped != 1 {
		t.Errorf("the run takes agent/sessions whole and copies one.json back into it while auth.json "+
			"stays skipped, but the plan reported Files: %d, Skipped: %d", plan.Files, plan.Skipped)
	}

	// The real run, on the tree the plan just read: what it does to the
	// stamps is the answer the plan is compared against below.
	fill(t, dest)

	copied, skipped := whatTheRunDid(t, filepath.Join(dest, "agent"))
	if copied != 1 || skipped != 1 {
		t.Fatalf("the real run copied %d and skipped %d, want one of each -- the comparison below is meaningless otherwise", copied, skipped)
	}
	if plan.Files != copied || plan.Skipped != skipped {
		t.Errorf("the plan said Files: %d, Skipped: %d; the run did Files: %d, Skipped: %d", plan.Files, plan.Skipped, copied, skipped)
	}
}

func TestThePlanRefusesAnExistingNonDirectoryProfile(t *testing.T) {
	home, dest := useProfile(t, []string{"agent"})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)
	if err := os.RemoveAll(dest); err != nil {
		t.Fatal(err)
	}
	write(t, dest, "this is not a profile directory")

	if _, _, err := Plan(dest, nil); err == nil {
		t.Fatal("the plan described a non-directory destination as a usable profile")
	}
}
