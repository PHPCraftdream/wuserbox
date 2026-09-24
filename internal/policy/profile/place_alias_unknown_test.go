package profile

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAnAliasMemoThatNeverGotAnAnswerKeepsTheQuestionOpen is the memo's
// read side, measured directly. The alias branch memoizes a question it
// could not finish -- the open of the alias spelling failed for a reason
// that is not the volume's own nothing -- and the memo's reader looked
// only at the canonical spelling that answer left empty. A second
// question about a DIFFERENT full spelling through the same unresolvable
// prefix read that emptiness as the volume's nothing: the false absence
// the round-11 fix drew the line against, arriving through the one book
// meant to remember the refusal. The memo keeps the whole answer, the
// unanswered one included, and a spelling nobody answered stays
// unanswered no matter how the next question spells it.
func TestAnAliasMemoThatNeverGotAnAnswerKeepsTheQuestionOpen(t *testing.T) {
	if !fileSystemJoins(t, "agent", "AGENT") {
		t.Skip("this volume holds agent and AGENT apart, so the alias branch has no answer to keep")
	}
	dest := t.TempDir()
	write(t, filepath.Join(dest, "agent", "auth.json"), `{"token":"real"}`)

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	// The directory behind an exclusive handle, and the question spelled
	// the way the volume would open it: the look fails with a sharing
	// violation, which is not the volume's own nothing.
	release := lockExclusive(t, filepath.Join(dest, "agent"), true)
	holdProof(t, root, "AGENT")

	resolver := newPlaceResolver(root)
	// The first question: the alias open is refused, the branch answers
	// unknown with its cause, and the memo keeps exactly that. Old and
	// new code agree here -- this is the answer the branch computes.
	first := resolver.canonicalEntryPath("AGENT/auth.json")
	if first.ok || !first.unknown || first.err == nil {
		t.Fatalf("the open the hold refused answered %+v, want the unanswered spelling with its cause", first)
	}
	// The second question: a different full spelling through the same
	// unresolvable prefix, which meets the memo before it opens anything
	// at all. The answer owed it is the refusal the first question got,
	// never the silence the memoized answer's empty canonical spelling
	// reads as.
	second := resolver.canonicalEntryPath("AGENT/session.json")
	if !second.unknown || second.err == nil {
		t.Fatalf("the second question through the memoized alias answered %+v, want the unanswered spelling with its cause: "+
			"the memo's refusal was read as the volume's nothing", second)
	}
	// The memo itself holds the refusal, under the joined path the branch
	// opens, exactly as the answered spellings are kept beside it.
	memo, ok := resolver.alias[filepath.Join(".", "AGENT")]
	if !ok || !memo.unknown || memo.err == nil {
		t.Errorf("the alias memo holds %v (present: %v), want the unanswered spelling kept with its cause", memo, ok)
	}
	// One enumeration of "." between the two questions: the second
	// question's walk read the memo, and the alias branch's opens of
	// stored spellings are resolution, not enumeration, and stay
	// uncounted by design.
	if resolver.opens != 1 {
		t.Errorf("two questions opened %d directories, want one: the second question opened nothing at all", resolver.opens)
	}
	release()
}

// TestAnAnswerTheListingCouldNotIndexStaysUnknownInTheMemo is the same
// defect's other arm, the one the partial scan's own comment names: the
// opened spelling canonicalizes onto a path the sibling scan's byCanonical
// index never gained, because the listing the scan walked predates the
// name. The volume opens the spelling -- the file is there -- and a sibling
// the scan could not open might be the one carrying the opened path, so no
// answer about this spelling was got at all. Old and new code agree on the
// answer the first question gets; the defect is what the branch MEMOIZED. A
// plain result went into the memo, and the question after it -- a different
// full spelling through the same unresolvable prefix -- read that silence as
// the volume's nothing. The memo now records exactly what the hand returns,
// so the question after it gets the same refusal.
func TestAnAnswerTheListingCouldNotIndexStaysUnknownInTheMemo(t *testing.T) {
	if !fileSystemJoins(t, "late.txt", "LATE.TXT") {
		t.Skip("this volume holds late.txt and LATE.TXT apart, so the alias open is an honest absence and the question cannot be staged")
	}
	dest := t.TempDir()
	write(t, filepath.Join(dest, "early.txt"), "early")

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	// The seed: snapshot "." before late.txt exists, then create it. The
	// alias opens on the live volume, but the incomplete scan cannot index
	// its canonical path because it walks the older listing.
	resolver := newPlaceResolver(root)
	if _, ok := resolver.snapshot("."); !ok {
		t.Fatal("could not snapshot the profile root")
	}
	if _, exists := resolver.dirs["."].byName["late.txt"]; exists {
		t.Fatal("the listing already carried late.txt, so this fixture cannot be staged")
	}
	if err := os.WriteFile(filepath.Join(dest, "late.txt"), []byte("late"), 0o644); err != nil {
		t.Fatal(err)
	}
	// early.txt behind an exclusive handle: share nothing, so the scan that
	// walks the stale listing is refused it alone, finishes incomplete, and
	// carries its cause. The unread sibling might be the one carrying the
	// opened path, so no answer about this spelling was got at all.
	release := lockExclusive(t, filepath.Join(dest, "early.txt"), false)
	holdProof(t, root, "early.txt")

	// The first question: the listing never carried LATE.TXT, so byName
	// misses and the alias branch runs. The open succeeds against the live
	// volume, and the scan over the stale listing is refused early.txt alone
	// and never indexes the opened path. Old and new code answer the same
	// unknown here -- the defect is what this hand memoized.
	first := resolver.canonicalEntryPath("LATE.TXT")
	if first.ok || !first.unknown || first.err == nil {
		t.Fatalf("the alias whose opened path the listing could not index answered %+v, want the unanswered spelling with its cause", first)
	}
	// The second question, a different full spelling through the same alias
	// prefix, reads the memo -- which now holds the refusal the first hand
	// returned, where it used to hold the plain result that read as the
	// volume's nothing.
	second := resolver.canonicalEntryPath("LATE.TXT/whatever")
	if !second.unknown || second.err == nil {
		t.Fatalf("the second question read %+v out of the alias memo, want the unanswered spelling with its cause: "+
			"the memoized silence was read as the volume's nothing", second)
	}
	memo, ok := resolver.alias[filepath.Join(".", "LATE.TXT")]
	if !ok || !memo.unknown || memo.err == nil {
		t.Errorf("the alias memo holds %v (present: %v), want the unanswered spelling kept with its cause", memo, ok)
	}
	// One partial scan and one enumeration of "." between the two questions:
	// the second question's walk read the memo, and opened nothing.
	if resolver.scans != 1 || resolver.opens != 1 {
		t.Errorf("two questions scanned %d sibling lists and opened %d directories, want one of each", resolver.scans, resolver.opens)
	}
	release()
}
