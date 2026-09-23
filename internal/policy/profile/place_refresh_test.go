package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestARespelledAnswerSurvivesARefreshWithoutAScan pins the completeness a
// directory's scan has to leave behind it, and the price of leaving it on
// the wrong copy. A snapshot is handed out by value -- the maps inside it
// are shared and its canonicalComplete flag is not -- so the alias scan
// that witnessed every child of a directory used to set the flag on the
// copy it held and leave the resolver's own table reading a stale false.
// The next rebuildCanonical read that flag, took a one-name answer for an
// answer the listing had never witnessed, and dropped it -- the unique
// answer to the very path the refresh had just restored -- so the alias
// spellings that follow a mirror paid a whole sibling scan for an answer
// this resolver already held. That is the loss the reviews of 2026-09-30
// (round 11) and 2026-09-23 (round 12) measured beside the other refresh
// costs, and the shape here is the smallest one that shows it.
//
// The fixture: one directory of eight files, one alias question about its
// last one, a mirror that respells that file, and a third spelling of the
// respelled file that no question has ever asked about -- so the alias
// memo has never heard of it and the only thing standing between the
// question and its answer is the snapshot's index.
func TestARespelledAnswerSurvivesARefreshWithoutAScan(t *testing.T) {
	if !fileSystemJoins(t, "q7", "Q7") {
		t.Skip("this volume holds q7 and Q7 apart, so there is no alias answer to keep")
	}
	dest := t.TempDir()
	for i := 0; i < 8; i++ {
		write(t, filepath.Join(dest, fmt.Sprintf("q%d", i)), "entry")
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	names := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		names = append(names, fmt.Sprintf("q%d", i))
	}
	index := newPlaceIndex(root, names)
	resolver := index.resolver

	// The first question about the directory in a spelling it does not
	// store: Q7. The alias branch opens the spelling, finds no answer for
	// the path it resolves onto, and pays the one sibling scan that
	// canonicalizes all eight children and witnesses the directory whole.
	first := resolver.place("Q7")
	if !first.ok || first.canonical != "q7" {
		t.Fatalf("the first alias question was answered %+v, want the stored spelling q7: the alias branch pays one sibling "+
			"scan and the index it leaves behind answers the question", first)
	}
	if resolver.scans != 1 {
		t.Fatalf("the first alias question cost %d sibling scans, want exactly one", resolver.scans)
	}

	// A mirror respells the last entry: the name moves, and the listing
	// the resolver holds is the enumeration taken before the move plus
	// the row the refresh writes for the name it stands under now.
	if err := os.Rename(filepath.Join(dest, "q7"), filepath.Join(dest, "q7x")); err != nil {
		t.Fatal(err)
	}
	if err := index.refresh("q7x"); err != nil {
		t.Fatalf("refreshing the operation index after the mirror respelled the entry: %v", err)
	}
	mapsBefore := resolver.canonicalMaps
	scansBefore := resolver.scans

	// The third question: a spelling of the respelled entry that no
	// earlier question asked about, so the alias memo has never heard of
	// it and only the snapshot's index stands between it and its answer.
	// The refresh walked the changed name's chain, added the new name's
	// rows and rebuilt its canonical answer -- one stored name under one
	// canonical path, in a directory a scan has already witnessed whole
	// -- so the answer is standing, and the question reads it instead of
	// asking the volume for the siblings again. The measurement is the
	// probe call itself, runs of one, because the first answer about a
	// spelling fills the memo and the question after it costs nothing
	// however wrong the answer was.
	var probe placeResult
	probeAllocs := testing.AllocsPerRun(1, func() { probe = resolver.place("Q7X") })
	if !probe.ok || probe.canonical != "q7x" {
		t.Fatalf("the repeat question about the respelled place was answered %+v, want the stored spelling q7x the refresh "+
			"restored: the scan's completeness never reached the resolver's table, so the rebuild that followed read a stale "+
			"false and took the unique answer back, leaving the spelling to be asked for as if it had never been resolved", probe)
	}
	if !sameEntryPlace(root, "Q7X", "q7x") {
		t.Fatal("a fresh resolver over the same unchanged files does not resolve Q7X either, so the fixture itself is broken")
	}
	if resolver.scans != scansBefore {
		t.Errorf("the repeat question cost %d sibling scans, want none: the answer it needed was the one the refresh "+
			"restored, and the volume was asked for the siblings all over again only because that answer had been dropped",
			resolver.scans-scansBefore)
	}
	if resolver.canonicalMaps != mapsBefore {
		t.Errorf("the repeat question rebuilt %d canonical membership maps, want none: every sibling it passed was already "+
			"answered, so the scan it paid for had nothing new to store and the maps the answers live in stood as they were",
			resolver.canonicalMaps-mapsBefore)
	}

	// The allocation side of the same bar, and the reason the bar is half
	// and not a hair: the same question over a fresh resolver over an
	// identical fixture pays the whole scan -- eight siblings opened and
	// canonicalized, their answers and their membership maps built --
	// while the repeat ask pays one resolution's own I/O, the open of the
	// spelling and the answer the volume hands back, and not a sibling
	// rebuild. The control resolver is built inside the measured call
	// because AllocsPerRun asks its closure twice, and a resolver built
	// outside it answers its second ask out of its own memo, so the
	// control would measure a cache hit instead of the scan it is here
	// to stand for. The sharp detectors are the scan and the membership
	// count above, which are exact and deterministic; this one says the
	// repeat question is not quietly paying the same bill through another
	// door.
	freshDest := t.TempDir()
	for i := 0; i < 8; i++ {
		write(t, filepath.Join(freshDest, fmt.Sprintf("q%d", i)), "entry")
	}
	freshRoot, err := os.OpenRoot(freshDest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = freshRoot.Close() }()
	freshAllocs := testing.AllocsPerRun(1, func() {
		fresh := newPlaceResolver(freshRoot)
		fresh.place("Q7")
	})
	if probeAllocs >= freshAllocs/2 {
		t.Errorf("the repeat question cost %.0f allocations and the same first question over a fresh resolver cost %.0f, want "+
			"the repeat to cost fewer than half: a repeat ask about an answer the refresh restored is one resolution, not "+
			"a sibling scan wearing a different name", probeAllocs, freshAllocs)
	}
}
