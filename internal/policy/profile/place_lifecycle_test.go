package profile

import (
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestARewriteKeepsTheStretchAndACreatedNameEndsIt(t *testing.T) {
	// The rewrite half: m0's source is gone, r1's source changed, m2's
	// source is gone, and the mirror between the two vouches rewrites a
	// standing file's bytes. One stretch answers both vouches.
	home, dest := useProfile(t, []string{"m0", "r1", "m2"})
	write(t, filepath.Join(home, "m0"), "abcd")
	write(t, filepath.Join(home, "r1"), "abcd")
	write(t, filepath.Join(home, "m2"), "abcd")
	fill(t, dest)

	write(t, filepath.Join(home, "r1"), "new bytes")
	if err := os.Remove(filepath.Join(home, "m0")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(home, "m2")); err != nil {
		t.Fatal(err)
	}

	stop := countingResolvers()
	copied := fill(t, dest)
	resolvers, opens, reads, resolutions, children, scans, _, _ := stop()
	if resolvers != 1 {
		t.Errorf("the run whose one mirror rewrote standing bytes built %d resolvers, want one: the bytes are not the names the stretch describes", resolvers)
	}
	if opens != 1 || reads != 1 {
		t.Errorf("the rewrite run opened %d directories and read %d of them, want one of each: one indexing of the record for both vouches", opens, reads)
	}
	if resolutions != 3 {
		t.Errorf("the rewrite run resolved %d spellings, want three: the record's three places, indexed once at the stretch's build, both vouches cache hits", resolutions)
	}
	if children != 3 {
		t.Errorf("the rewrite run processed %d children, want three: the profile root's three entries, once", children)
	}
	if scans != 0 {
		t.Errorf("the rewrite run scanned the profile root's siblings %d times, want none: every spelling is exact, so no alias branch runs", scans)
	}
	if got := read(t, filepath.Join(dest, "r1")); got != "new bytes" {
		t.Errorf("the rewritten source did not land: %q", got)
	}
	if !reflect.DeepEqual(pathsOf(copied), []string{"m0", "r1", "m2"}) {
		t.Errorf("the record came back as %v, want all three entries", pathsOf(copied))
	}

	// The created-name half: c1's copy is gone from the destination, its
	// source stands, and the mirror between the two vouches makes the name
	// again. The stretch dies on it, and the last vouch builds a fresh
	// resolver -- two, where the rewrite half above held one.
	home2, dest2 := useProfile(t, []string{"m0", "c1", "m2"})
	write(t, filepath.Join(home2, "m0"), "abcd")
	write(t, filepath.Join(home2, "c1"), "abcd")
	write(t, filepath.Join(home2, "m2"), "abcd")
	fill(t, dest2)

	if err := os.Remove(filepath.Join(dest2, "c1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(home2, "m0")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(home2, "m2")); err != nil {
		t.Fatal(err)
	}

	stop = countingResolvers()
	copied = fill(t, dest2)
	resolvers, opens, reads, resolutions, children, scans, _, _ = stop()
	if resolvers != 1 {
		t.Errorf("the run whose mirror made the lost name again built %d resolvers, want one: the stretch updates the created name in place", resolvers)
	}
	if opens != 1 || reads != 1 {
		t.Errorf("the create run opened %d directories and read %d of them, want one initial index", opens, reads)
	}
	if resolutions != 4 {
		t.Errorf("the create run resolved %d spellings, want four: three initial places and the created name refreshed once", resolutions)
	}
	if children != 2 {
		t.Errorf("the create run processed %d children, want two: the root's initial listing", children)
	}
	if scans != 0 {
		t.Errorf("the create run scanned the profile root's siblings %d times, want none: every spelling is exact, so no alias branch runs", scans)
	}
	if got := read(t, filepath.Join(dest2, "c1")); got != "abcd" {
		t.Errorf("the lost copy was not made whole again: %q", got)
	}
	if !reflect.DeepEqual(pathsOf(copied), []string{"m0", "c1", "m2"}) {
		t.Errorf("the record came back as %v, want all three entries", pathsOf(copied))
	}
}

// TestAClearThatTookNothingBackKeepsTheStretchAndOneThatClearedRetractsItsAnswers
// pins the same line on the take-back, where clearEntry's own answer is
// the question: stale entries whose copies are already gone from the
// profile answer false, take nothing back, and share one stretch of
// instruments -- the shape that used to rebuild after every clear, whatever
// the clear had done -- while a clear that really removed a name retracts
// the answers it made false and the stretch stands on them, the scoped
// take-back the review of 2026-09-26 (P3-1),
// docs/reviews/security-performance-review-2026-09-26-round6.md, replaced
// the wholesale death with. forget is called directly, with the record and
// the list a run would hand it, so the counted bill is the take-back's
// alone.
func TestAClearThatTookNothingBackKeepsTheStretchAndOneThatClearedRetractsItsAnswers(t *testing.T) {
	// Nothing taken: a0 and a1 left the list and their copies are already
	// gone from the profile; k0 stays named and stands. Both clears find
	// an empty place, and one stretch answers both questions.
	dest := t.TempDir()
	write(t, filepath.Join(dest, "k0"), "kept")
	previous := []config.Entry{{Path: "a0"}, {Path: "a1"}, {Path: "k0"}}
	current := []config.Entry{{Path: "k0"}}

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	stop := countingResolvers()
	if err := forget(root, previous, current); err != nil {
		t.Fatal(err)
	}
	resolvers, opens, reads, resolutions, children, scans, visits, _ := stop()
	_ = root.Close()

	if resolvers != 1 {
		t.Errorf("the pass whose clears took nothing back built %d resolvers, want one: a clear that found nothing to take changed no name, and the next question reads the same instruments", resolvers)
	}
	if opens != 1 || reads != 1 {
		t.Errorf("the nothing-taken pass opened %d directories and read %d of them, want one of each: the stretch's one indexing of the current list", opens, reads)
	}
	if resolutions != 3 {
		t.Errorf("the nothing-taken pass resolved %d spellings, want three: k0 indexed at the stretch's build, a0 and a1 asked once each and answered by the volume's nothing", resolutions)
	}
	if children != 1 {
		t.Errorf("the nothing-taken pass processed %d children, want one: the profile root's one standing entry, once for the whole pass", children)
	}
	if scans != 0 {
		t.Errorf("the nothing-taken pass scanned the profile root's siblings %d times, want none: every spelling is exact, so no alias branch runs", scans)
	}
	if visits != 0 {
		t.Errorf("the nothing-taken pass pulled %d book entries in retractions, want none: no clear took anything back, so no retraction ran", visits)
	}
	if got := read(t, filepath.Join(dest, "k0")); got != "kept" {
		t.Errorf("the surviving entry was disturbed by the clears beside it: %q", got)
	}

	// Something taken: b0 and b1 left the list and their copies stand. The
	// first clear removes a real name, and retract takes back the answers
	// it made false -- b0's witnessed resolution, and b0's rows in the
	// root's books -- while the stretch itself stands: b1's question then
	// reads the root's amended listing, the taken name out of the index
	// and the survivors standing, and no enumeration is paid for it at
	// all. k0 is never asked again, its resolution and its seat in the
	// presence set the survivors the retraction kept. One resolver, one
	// enumeration, three resolutions, where the replaced shape -- the
	// stretch dying on every real clear -- built again and re-indexed k0
	// once per clear, and the round-6 shape paid a re-enumeration of the
	// root after each real clear on top. This half is the invariant: a
	// retract that dropped more than the clear had made false, or kept a
	// listing the clear had changed, would leave this stretch answering
	// from a stale place or paying for its survivors twice.
	dest = t.TempDir()
	write(t, filepath.Join(dest, "b0"), "stale")
	write(t, filepath.Join(dest, "b1"), "stale")
	write(t, filepath.Join(dest, "k0"), "kept")
	previous = []config.Entry{{Path: "b0"}, {Path: "b1"}, {Path: "k0"}}

	root, err = os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	stop = countingResolvers()
	if err := forget(root, previous, current); err != nil {
		t.Fatal(err)
	}
	resolvers, opens, reads, resolutions, children, scans, visits, _ = stop()
	_ = root.Close()

	if resolvers != 1 {
		t.Errorf("the pass whose first clear removed a name built %d resolvers, want one: the real clear retracts the answers it made false and the stretch survives it, where the shape the review of 2026-09-26 (P3-1) replaced ended the stretch and made the next question build fresh instruments", resolvers)
	}
	if opens != 1 || reads != 1 {
		t.Errorf("the real-clear pass opened %d directories and read %d of them, want one of each: the stretch's build, the pass's only enumeration -- retract amends the holding directory's listing in place, where the round-6 shape took the snapshot back and made b1's question re-read the root the clear emptied", opens, reads)
	}
	if resolutions != 3 {
		t.Errorf("the real-clear pass resolved %d spellings, want three: k0 indexed once at the build and never asked again, b0 and b1 asked once each -- the survivors' resolutions are what retract keeps, where the replaced shape paid for k0 once per real clear", resolutions)
	}
	if children != 3 {
		t.Errorf("the real-clear pass processed %d children, want three: the root's three entries at the build, the pass's only enumeration, where the round-6 shape paid a second enumeration's two after b0's clear", children)
	}
	if scans != 0 {
		t.Errorf("the real-clear pass scanned the profile root's siblings %d times, want none: every spelling is exact, so no alias branch runs", scans)
	}
	if visits != 2 {
		t.Errorf("the real-clear pass pulled %d book entries in retractions, want two: each real clear takes back exactly the witnessed spelling it made false, and nothing besides -- no alias answers stand to take, and no snapshot sits beneath the places taken", visits)
	}
	if _, err := os.Stat(filepath.Join(dest, "b0")); !os.IsNotExist(err) {
		t.Errorf("the stale b0 survived its clear: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "b1")); !os.IsNotExist(err) {
		t.Errorf("the stale b1 survived its clear: %v", err)
	}
	if got := read(t, filepath.Join(dest, "k0")); got != "kept" {
		t.Errorf("the surviving entry was disturbed by the clears beside it: %q", got)
	}
}

// BenchmarkDedupeEntriesThePairwiseWay runs the loop this branch replaced
// over the same warm tree as BenchmarkDedupeEntries, so the resolver's
// saving stands as one number beside another rather than an adjective. It
// is deliberately no longer the production path; it is the old side of the
// measurement the review's close test asks to keep honest.
func BenchmarkDedupeEntriesThePairwiseWay(b *testing.B) {
	dest := warmTree(b)
	entries := warmEntries()
	root, err := os.OpenRoot(dest)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		legacyDedupe(root, entries, &dirCounts{})
	}
	b.ReportAllocs()
}
