package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
)

// dirCounts is the counter the P2-5 close test reads: one tick per
// directory open, one per ReadDir, in whichever code under measurement is
// walking.
type dirCounts struct {
	opens int
	reads int
}

// legacyCanonicalEntryPath is canonicalEntryPath as this branch found it:
// every call opens and ReadDirs every component's directory again, and
// nothing is kept between calls. It is here and not in production so the
// measurement can run both algorithms over one tree -- the resolver
// answers from snapshots and indexes, and the number this walk clocks is
// what that saves. The review's P2-5 was this walk, asked once per
// comparison.
func legacyCanonicalEntryPath(root *os.Root, path string, count *dirCounts) (string, bool) {
	clean := cleanEntryPath(path)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", false
	}
	current := "."
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		count.opens++
		dir, err := root.Open(current)
		if err != nil {
			return "", false
		}
		count.reads++
		children, err := dir.ReadDir(-1)
		_ = dir.Close()
		if err != nil {
			return "", false
		}
		chosen := ""
		for _, child := range children {
			if child.Name() == component {
				chosen = child.Name()
				break
			}
		}
		if chosen == "" {
			opened, err := root.Open(filepath.Join(current, component))
			if err != nil {
				return "", false
			}
			openedPath, err := pathid.Canonical(opened.Name())
			_ = opened.Close()
			if err != nil {
				return "", false
			}
			matches := 0
			for _, child := range children {
				childFile, err := root.Open(filepath.Join(current, child.Name()))
				if err != nil {
					continue
				}
				childPath, childErr := pathid.Canonical(childFile.Name())
				_ = childFile.Close()
				if childErr == nil && childPath == openedPath {
					chosen = child.Name()
					matches++
				}
			}
			if matches != 1 {
				return "", false
			}
		}
		if chosen == "" {
			return "", false
		}
		current = filepath.Join(current, chosen)
	}
	return current, true
}

func legacySameEntryPlace(root *os.Root, first, second string, count *dirCounts) bool {
	opened, ok := legacyCanonicalEntryPath(root, first, count)
	if !ok {
		return false
	}
	other, ok := legacyCanonicalEntryPath(root, second, count)
	return ok && opened == other
}

// legacyStillNamed is stillNamed as this branch found it: a fresh resolver
// per current entry compared, no canonical-presence index and nothing kept
// between comparisons, so a pass over P recorded entries against C current
// ones walks the tree once per surviving pair. It is here and not in
// production so the whole-Copy counter can put both shapes to one tree and
// hold the answers equal, entry for entry, before it holds the costs apart.
func legacyStillNamed(root *os.Root, current []config.Entry, recorded string, count *dirCounts) bool {
	cleaned := cleanEntryPath(recorded)
	for _, entry := range current {
		if cleanEntryPath(entry.Path) == cleaned {
			return true
		}
		if legacySameEntryPlace(root, entry.Path, recorded, count) {
			return true
		}
	}
	return false
}

// legacyRecordVouches is recordVouches as this branch found it: one fresh
// walk per recorded entry asked about, the entry's own place re-walked for
// every one of them, so vouching one entry against a record of R names is R
// pairwise comparisons and a missing source's question costs the record
// whole. Kept beside legacyStillNamed for the same reason: the counter has
// to certify the new shape answers what the old one answered, or its
// cheaper numbers are about nothing.
func legacyRecordVouches(root *os.Root, recorded []string, entry string, count *dirCounts) bool {
	for _, path := range recorded {
		if legacySameEntryPlace(root, path, entry, count) {
			return true
		}
	}
	return false
}

// legacyDedupe is DedupeEntries as the pairwise loop this branch replaced,
// kept for the same reason its two helpers are: the counter has to run both
// algorithms over one tree, or it proves nothing about what changed. The
// short-circuits are the loop's own -- a cleaned spelling already kept
// drops the entry before the volume is asked anything.
func legacyDedupe(root *os.Root, entries []config.Entry, count *dirCounts) []config.Entry {
	kept := make([]config.Entry, 0, len(entries))
	for _, entry := range entries {
		duplicate := false
		for _, prior := range kept {
			if cleanEntryPath(prior.Path) == cleanEntryPath(entry.Path) ||
				legacySameEntryPlace(root, prior.Path, entry.Path, count) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			kept = append(kept, entry)
		}
	}
	return kept
}

// TestDedupeEntriesResolvesEachEntryOnce is the counter the review asked
// for (P2-5). Four two-component entries over four directories, plus a
// spelling that repeats, are deduped the way a run dedupes them: through
// one resolver for the whole call. The operation is held to one open and
// one ReadDir per directory the walks pass through -- the root and the
// four parents, five; a place itself is never enumerated, only the
// directories its components are found in -- where the pairwise loop this
// replaced clocks twenty-eight of each over the same tree, because it
// walked both spellings' directories fresh for every comparison. The kept
// list itself has to be the pairwise loop's, entry for entry and in order,
// or the counter would be certifying a cheaper way of answering
// differently.
func TestDedupeEntriesResolvesEachEntryOnce(t *testing.T) {
	dest := t.TempDir()
	for _, dir := range []string{"a/one", "b/two", "c/three", "d/four"} {
		if err := os.MkdirAll(filepath.Join(dest, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	entries := []config.Entry{
		{Path: "a/one"}, {Path: "b/two"}, {Path: "c/three"}, {Path: "d/four"}, {Path: "b/two"},
	}

	var built []*placeResolver
	previous := newPlaceResolver
	newPlaceResolver = func(root *os.Root) *placeResolver {
		resolver := previous(root)
		built = append(built, resolver)
		return resolver
	}
	defer func() { newPlaceResolver = previous }()

	got := DedupeEntries(dest, entries)
	if len(built) != 1 {
		t.Fatalf("one dedupe built %d resolvers, and one operation is one resolver", len(built))
	}
	if want := []string{"a/one", "b/two", "c/three", "d/four"}; !reflect.DeepEqual(pathsOf(got), want) {
		t.Errorf("the record came back as %v, want %v", pathsOf(got), want)
	}
	if built[0].opens != 5 || built[0].reads != 5 {
		t.Errorf("deduping five entries opened %d directories and read %d of them, want five of each: "+
			"the root once and each entry's parent once, whatever the number of comparisons",
			built[0].opens, built[0].reads)
	}

	// The same call as the branch found it, over the same tree: seven
	// comparisons survive the spelling short-circuit, and each walked both
	// spellings' directories from scratch -- four directories apiece,
	// twenty-eight opens and twenty-eight reads in all.
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	var legacy dirCounts
	legacyDedupe(root, entries, &legacy)
	if legacy.opens != 28 || legacy.reads != 28 {
		t.Errorf("the pairwise loop clocked %d opens and %d reads, want 28 of each over this tree",
			legacy.opens, legacy.reads)
	}
	if legacy.opens <= built[0].opens || legacy.reads <= built[0].reads {
		t.Errorf("the resolver saved nothing measurable: %d opens and %d reads against the loop's %d and %d",
			built[0].opens, built[0].reads, legacy.opens, legacy.reads)
	}
}

// TestSameEntryPlaceSharesOneLookBetweenItsTwoSpellings pins the resolver's
// other half. stillNamed and recordVouches now hold one resolver across each
// whole question-set -- stillNamed across one recorded entry against the
// whole current list, recordVouches across the whole record for one entry --
// and this test pins the one-comparison seam sameEntryPlace itself keeps,
// where the two spellings must not each walk the tree from scratch: the
// second is asked under its own cleaned key and reads nothing the first has
// not already read. One comparison over one place, the second spelling in the capitals
// the volume joins, is held to two opens and two reads -- the root and the
// place's parent, once between them; the place itself is found in its
// parent's listing and is never enumerated.
func TestSameEntryPlaceSharesOneLookBetweenItsTwoSpellings(t *testing.T) {
	if !fileSystemJoins(t, "one", "ONE") {
		t.Skip("this volume holds one and ONE apart, so there is no shared look to count")
	}
	dest := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dest, "one", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}

	var built []*placeResolver
	previous := newPlaceResolver
	newPlaceResolver = func(root *os.Root) *placeResolver {
		resolver := previous(root)
		built = append(built, resolver)
		return resolver
	}
	defer func() { newPlaceResolver = previous }()

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	if !sameEntryPlace(root, "one/deep", "ONE/DEEP") {
		t.Fatal("two spellings of one place did not resolve onto it")
	}
	if len(built) != 1 {
		t.Fatalf("one comparison built %d resolvers, and one comparison is one resolver", len(built))
	}
	if built[0].opens != 2 || built[0].reads != 2 {
		t.Errorf("one comparison opened %d directories and read %d of them, want two of each: "+
			"the second spelling's walk reads from the first's snapshots",
			built[0].opens, built[0].reads)
	}
}

// countingResolvers swaps newPlaceResolver for a wrapper that keeps every
// resolver an operation builds while it is installed, and hands back the
// func that stops it: the real constructor goes back before anything is
// reported, so the legacy walks and the next phase run against the
// production path as it was found, and a test that dies between an install
// and its stop leaves the wrapper installed, and the wrapper answers as
// the constructor it wrapped, so nothing downstream can tell. The stop
// reports how many resolvers were built and the opens and reads they paid
// for together.
func countingResolvers() func() (resolvers, opens, reads int) {
	var held []*placeResolver
	previous := newPlaceResolver
	newPlaceResolver = func(root *os.Root) *placeResolver {
		resolver := previous(root)
		held = append(held, resolver)
		return resolver
	}
	return func() (resolvers, opens, reads int) {
		newPlaceResolver = previous
		resolvers = len(held)
		for _, resolver := range held {
			opens += resolver.opens
			reads += resolver.reads
		}
		held = nil
		return resolvers, opens, reads
	}
}

// TestAWarmCopyPaysResolverWorkOncePerEntryNotOncePerPair is the counter the
// review asked for (P2-4), and it brackets a whole Copy rather than one
// operation inside it: forget's stillNamed pass and copyEntries'
// recordVouches calls are the two places a warm run used to build a fresh
// resolver per pairwise comparison, and their bill arrived together -- an
// already-copied profile whose bytes had not changed paid for every
// recorded entry against every current one, on every run.
//
// The profile is warmed once, uncounted. What is counted is what a warm run
// does when there is nothing left to copy: the entries respelled between
// runs in reversed order and in the capitals the volume joins, so every
// stillNamed question misses the cleaned-spelling short-circuit and has to
// ask the volume about every current entry before the recorded one's place
// turns up in the set; the sources deleted outright, so every entry takes
// the recordVouches path instead of the copy; and one entry finally dropped
// from the list, so forget's pass has to answer a false and take the copy
// it leaves behind. Between the counted fills, the same three questions are
// put to legacyStillNamed and legacyRecordVouches -- the old
// one-resolver-per-pair shape -- over the same tree, before that tree is
// mutated, and their answers are held to the new shape's, entry for entry.
//
// On a volume that joins e0 and E0, a question costs at most one enumeration
// of the profile root: its first miss opens the root, and everything after
// that -- the respelled spellings, the rest of the record, the rest of the
// current list -- is answered out of that snapshot, its byName index and its
// alias book, whose opens are resolution and not enumeration. The old shape
// walked both spellings' directories fresh for every pair its short-circuits
// left standing.
func TestAWarmCopyPaysResolverWorkOncePerEntryNotOncePerPair(t *testing.T) {
	if !fileSystemJoins(t, "e0", "E0") {
		t.Skip("this volume holds e0 and E0 apart, so a respelling names a different place and there is nothing to count")
	}
	const k = 6
	names := make([]string, 0, k)
	for i := 0; i < k; i++ {
		names = append(names, fmt.Sprintf("e%d", i))
	}
	// Reversed and capitalized: E5 first and E0 last, so a recorded e_i
	// sits behind every other current spelling and a current E_i sits
	// behind every recorded spelling that cannot match it.
	caps := make([]string, 0, k)
	for i := k - 1; i >= 0; i-- {
		caps = append(caps, fmt.Sprintf("E%d", i))
	}
	capsEntries := config.Entries(caps)

	home, dest := useProfile(t, names)
	for _, name := range names {
		write(t, filepath.Join(home, name, "keep.txt"), "copied")
	}

	// The warming run, uncounted: everything lands and the record comes
	// back [e0..e5], the spellings the next run's questions are asked
	// about.
	fill(t, dest)

	// The rules file respelled, and the old shape's answers to the same
	// questions this run is about to answer -- taken now, while dest still
	// holds exactly what the warming run left, because the fill below
	// mutates the directories both algorithms describe.
	if err := (&config.Config{Profile: config.Entries(caps)}).Save(); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	var legacy dirCounts
	for _, name := range names {
		if !legacyStillNamed(root, capsEntries, name, &legacy) {
			t.Errorf("the pairwise stillNamed said the respelled list no longer names %s, and the run it describes would have cleared a copy the list still names", name)
		}
	}
	_ = root.Close()
	if legacy.opens != 42 || legacy.reads != 42 {
		t.Errorf("the pairwise stillNamed pass over six recorded entries against six respelled current ones "+
			"clocked %d opens and %d reads, want 42 of each: the pairs its spelling short-circuit leaves "+
			"standing come to six plus five plus four plus three plus two plus one, and every pair walked "+
			"both spellings' directories fresh", legacy.opens, legacy.reads)
	}

	// Phase 2, the warm respelled run: no byte has changed, so this is the
	// run that used to pay per pair.
	stop := countingResolvers()
	defer stop()
	copied := fill(t, dest)
	resolvers, opens, reads := stop()
	totalResolvers, totalOpens, totalReads := resolvers, opens, reads
	if resolvers != 6 {
		t.Errorf("the warm respelled run built %d resolvers, want six: forget answered six recorded entries "+
			"with six resolvers, and copyEntries found every source on the volume and never reached the record",
			resolvers)
	}
	if opens != 6 || reads != 6 {
		t.Errorf("the warm respelled run opened %d directories and read %d of them, want six of each: forget "+
			"answered six recorded entries with six enumerated directories -- one snapshot of the profile root "+
			"per question, not one per pair -- and the respelled spellings were answered out of that snapshot's "+
			"alias book, whose opens are resolution and not enumeration", opens, reads)
	}
	if !reflect.DeepEqual(pathsOf(copied), caps) {
		t.Errorf("the record came back as %v, want %v: the record follows the new spellings, not the stored ones", pathsOf(copied), caps)
	}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dest, name, "keep.txt")); err != nil {
			t.Errorf("the destination's copy of %s did not survive the run that respelled it in the list: %v", name, err)
		}
	}
	if held := namesOf(t, dest); !reflect.DeepEqual(held, names) {
		t.Errorf("the destination holds %v, want the entries under the spellings they were stored under", held)
	}

	// The sources go the way sources do, and the record -- spelled in
	// capitals now -- is the only witness left for the copies. The old
	// shape's answers first, over the tree the next fill finds.
	for _, name := range names {
		if err := os.RemoveAll(filepath.Join(home, name)); err != nil {
			t.Fatal(err)
		}
	}
	root, err = os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	var legacyMissing dirCounts
	for _, entry := range caps {
		if !legacyRecordVouches(root, caps, entry, &legacyMissing) {
			t.Errorf("the pairwise recordVouches said the record does not vouch for %s, and the run it describes would have dropped a copy nothing else can restore", entry)
		}
	}
	_ = root.Close()
	if legacyMissing.opens != 42 || legacyMissing.reads != 42 {
		t.Errorf("the pairwise recordVouches pass over six entries against a record of six clocked %d opens "+
			"and %d reads, want 42 of each: each entry pairs against the record until its own spelling turns "+
			"up -- one plus two plus three plus four plus five plus six pairs -- and every pair walked both "+
			"spellings' directories fresh", legacyMissing.opens, legacyMissing.reads)
	}

	// Phase 3, every source gone: forget's answers come from the record and
	// the rules spelling alike, and copyEntries' from the record alone -- but
	// an answer by spelling only short-circuits the question it meets, and
	// every current entry met ahead of the match still has its place indexed
	// on the way.
	stop = countingResolvers()
	copied = fill(t, dest)
	resolvers, opens, reads = stop()
	totalResolvers, totalOpens, totalReads = totalResolvers+resolvers, totalOpens+opens, totalReads+reads
	if resolvers != 12 {
		t.Errorf("the run with every source gone built %d resolvers, want twelve: six stillNamed resolvers "+
			"that asked the volume nothing -- the record and the rules spell the entries alike -- and six "+
			"recordVouches resolvers, one per source that os.Stat could not find", resolvers)
	}
	if opens != 11 || reads != 11 {
		t.Errorf("the run with every source gone opened %d directories and read %d of them, want eleven of each: "+
			"the twelve questions were answered with twelve resolvers and eleven snapshots of the profile root -- "+
			"one per question that reached the volume, shared by every place that question asked about. Five of the "+
			"six forget questions met a respelled current entry ahead of their spelling match and indexed its place "+
			"on the way, and each of the six recordVouches questions resolved the entry's own place first; only the "+
			"recorded entry whose match sat at the head of the list asked for none", opens, reads)
	}
	if !reflect.DeepEqual(pathsOf(copied), caps) {
		t.Errorf("the record came back as %v, want %v: every entry stays on the record the copy's witness vouches for", pathsOf(copied), caps)
	}

	// Phase 4, the list drops its last entry. The old shape's answer about
	// the recorded E0 against the shortened list, before the fill that
	// acts on it.
	shortened := caps[:k-1]
	root, err = os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	var legacyDropped dirCounts
	if legacyStillNamed(root, config.Entries(shortened), "E0", &legacyDropped) {
		t.Error("the pairwise stillNamed said the shortened list still names E0, and the copy it holds would never be taken back")
	}
	_ = root.Close()
	if legacyDropped.opens != 10 || legacyDropped.reads != 10 {
		t.Errorf("the pairwise stillNamed pass over the recorded E0 against the five shortened entries clocked "+
			"%d opens and %d reads, want 10 of each: five pairs survive the spelling short-circuit and every "+
			"pair walked both spellings' directories fresh", legacyDropped.opens, legacyDropped.reads)
	}
	if err := (&config.Config{Profile: config.Entries(shortened)}).Save(); err != nil {
		t.Fatal(err)
	}
	stop = countingResolvers()
	copied = fill(t, dest)
	resolvers, opens, reads = stop()
	totalResolvers, totalOpens, totalReads = totalResolvers+resolvers, totalOpens+opens, totalReads+reads
	if resolvers != 11 {
		t.Errorf("the run that dropped an entry built %d resolvers, want eleven: five stillNamed resolvers the "+
			"record and the rules spelled alike, a sixth for the recorded entry the shortened list stopped "+
			"naming, and five recordVouches resolvers for the sources still gone", resolvers)
	}
	if opens != 10 || reads != 10 {
		t.Errorf("the run that dropped an entry opened %d directories and read %d of them, want ten of each: "+
			"eleven questions answered with ten snapshots of the profile root, one per question that reached the "+
			"volume -- four forget questions whose respelled current entries sat ahead of their spelling matches, "+
			"the recorded entry the list stopped naming, and the five sources os.Stat could not find. Only the "+
			"first recorded entry's question, answered at the head of the list, asked for none", opens, reads)
	}
	if !reflect.DeepEqual(pathsOf(copied), shortened) {
		t.Errorf("the record came back as %v, want %v: the entry the list dropped goes, the entries it kept stay", pathsOf(copied), shortened)
	}
	if _, err := os.Stat(filepath.Join(dest, "e0")); !os.IsNotExist(err) {
		t.Errorf("the list dropped E0 and the copy it held stayed: %v", err)
	}
	for _, name := range names[1:] {
		if _, err := os.Stat(filepath.Join(dest, name, "keep.txt")); err != nil {
			t.Errorf("the copy under %s was disturbed by the run that dropped a different entry: %v", name, err)
		}
	}

	// The review's point, as totals: the resolver's whole share of three
	// warm runs is one enumeration of the profile root per question that
	// reached it, while the pairwise shape re-walked both spellings of
	// every pair its short-circuits left standing -- more than twice as
	// hard at six entries, and the gap grows with the square.
	if totalResolvers != 29 {
		t.Errorf("the three counted runs built %d resolvers, want 29 -- six and twelve and eleven: one per "+
			"stillNamed question and one per recordVouches question, whatever the lists they ask about hold",
			totalResolvers)
	}
	if totalOpens != 27 || totalReads != 27 {
		t.Errorf("the three counted runs opened %d directories and read %d of them, want 27 of each: "+
			"twenty-nine questions, twenty-seven of which reached the volume, each for exactly one snapshot of the "+
			"profile root shared by every place that question asked about -- the two whose spelling match sat at "+
			"the head of the list asked for none", totalOpens, totalReads)
	}
	legacyOpens := legacy.opens + legacyMissing.opens + legacyDropped.opens
	legacyReads := legacy.reads + legacyMissing.reads + legacyDropped.reads
	if legacyOpens != 94 || legacyReads != 94 {
		t.Errorf("the pairwise shape clocked %d opens and %d reads across the three walks, want 94 of each -- "+
			"42, 42 and 10: the pairs its short-circuits left standing walked both spellings' directories fresh",
			legacyOpens, legacyReads)
	}
	if legacyOpens <= totalOpens || legacyReads <= totalReads {
		t.Errorf("the pairwise shape clocked %d opens and %d reads against the resolver's %d and %d, and the "+
			"review's point -- a warm copy pays per entry, not per pair -- does not show at K=%d",
			legacyOpens, legacyReads, totalOpens, totalReads, k)
	}
}

// TestAliasAnswersAreKeptForTheQuestionsThatFollow reads the resolver's own
// books, because the opens/reads counters cannot see the machinery this
// pins: an alias open is resolution, not enumeration, and is uncounted by
// design. The exact-spelling index and the alias memo are what keep a
// resolver's second question about one spelling from opening anything at
// all -- the first alias query in a directory fills the snapshot's
// sibling-canonical cache, and the second query about the same spelling,
// reached through a different cleaned path, reads the memo instead of
// opening the spelling and its siblings again.
func TestAliasAnswersAreKeptForTheQuestionsThatFollow(t *testing.T) {
	if !fileSystemJoins(t, "e5", "E5") {
		t.Skip("this volume holds e5 and E5 apart, so there is no alias answer to keep")
	}
	dest := t.TempDir()
	write(t, filepath.Join(dest, "e5", "x"), "x")
	write(t, filepath.Join(dest, "e5", "y"), "y")

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	resolver := newPlaceResolver(root)

	if !resolver.samePlace("E5/x", "e5/x") {
		t.Fatal("two spellings of one place did not resolve onto it, so there is no alias answer to keep")
	}
	if !resolver.samePlace("E5/y", "e5/y") {
		t.Fatal("the second spelling question was answered differently than the first")
	}
	// Both comparisons answered from one enumeration each of "." and
	// "e5": the second comparison is a different cleaned path through the
	// same spellings, and it added nothing.
	if resolver.opens != 2 || resolver.reads != 2 {
		t.Errorf("two comparisons opened %d directories and read %d of them, want two of each: the root and "+
			"e5, once between the four questions", resolver.opens, resolver.reads)
	}
	// The alias answer for E5 was computed once and kept, under the joined
	// path the alias branch opens.
	memo, ok := resolver.alias[filepath.Join(".", "E5")]
	if !ok || !memo.ok || memo.canonical != "e5" {
		t.Errorf("the alias book holds %v for E5 (present: %v), want the stored spelling e5 computed once and kept", memo, ok)
	}
	// The sibling scan ran once: the one child of "." has its canonical
	// spelling kept in the snapshot, where the second query's scan read
	// it.
	snap, ok := resolver.dirs["."]
	if !ok {
		t.Fatal("the root was never snapshotted, so nothing here was measured")
	}
	if len(snap.canonical) != 1 {
		t.Errorf("the sibling scan left %d canonical spellings in the root's snapshot (%v), want one -- e5, the only child",
			len(snap.canonical), snap.canonical)
	}
	if kept, ok := snap.canonical["e5"]; !ok || kept == "" {
		t.Errorf("the root's snapshot holds %v, and its one child's canonical spelling is missing from it", snap.canonical)
	}
	if _, ok := resolver.dirs["e5"]; !ok {
		t.Error("e5 was never snapshotted, though both comparisons resolved a file inside it")
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
