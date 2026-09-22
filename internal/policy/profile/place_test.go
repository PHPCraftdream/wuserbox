package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
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

// legacyStillNamed is forget's ownership question in the pairwise shape the
// resolver work found: a fresh resolver per current entry compared, no
// canonical-presence index and nothing kept
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

// legacyPerQuestionStillNamed is forget's ownership question as this fix
// found it: the resolver was killed after every question, so a pass over
// the record built a fresh resolver per recorded entry and enumerated the
// profile root once per question -- every question's own opens and reads
// looked perfectly linear, and the square hid in the children each
// enumeration processed, which no counter was reading. It builds through
// defaultPlaceResolver rather than the newPlaceResolver variable, so a
// counting test's wrapper cannot swallow its resolvers, and it reports the
// children its enumerations processed beside the answer, so the stretch
// shape's numbers have something honest to stand against.
func legacyPerQuestionStillNamed(root *os.Root, current []config.Entry, recorded string, count *dirCounts) (bool, int) {
	resolver := defaultPlaceResolver(root)
	cleaned := cleanEntryPath(recorded)
	places := make(map[string]bool, len(current))
	named := false
	for _, entry := range current {
		if cleanEntryPath(entry.Path) == cleaned {
			named = true
			break
		}
		if canonical, ok := resolver.place(entry.Path); ok {
			places[canonical] = true
		}
	}
	if !named {
		recordedPlace, ok := resolver.place(recorded)
		named = ok && places[recordedPlace]
	}
	count.opens += resolver.opens
	count.reads += resolver.reads
	return named, resolver.children
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
// other half. forget and copyEntries now hold one resolver across each
// mutation-free stretch of their loops -- forget over its recorded entries,
// copyEntries over its missing sources -- and drop it after the real
// mutation, forget's clearEntry and copyEntries' mirror, that would turn
// its cached answers into lies. This test pins the one-comparison seam
// sameEntryPlace itself keeps,
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
// reports how many resolvers were built and the opens and reads and
// resolutions and children and scans they paid for together.
func countingResolvers() func() (resolvers, opens, reads, resolutions, children, scans int) {
	var held []*placeResolver
	previous := newPlaceResolver
	newPlaceResolver = func(root *os.Root) *placeResolver {
		resolver := previous(root)
		held = append(held, resolver)
		return resolver
	}
	return func() (resolvers, opens, reads, resolutions, children, scans int) {
		newPlaceResolver = previous
		resolvers = len(held)
		for _, resolver := range held {
			opens += resolver.opens
			reads += resolver.reads
			resolutions += resolver.resolutions
			children += resolver.children
			scans += resolver.scans
		}
		held = nil
		return resolvers, opens, reads, resolutions, children, scans
	}
}

// TestAWarmCopyPaysResolverWorkOncePerEntryNotOncePerPair is the counter the
// review asked for (P2-4), and it brackets a whole Copy rather than one
// operation inside it: forget's pass over the record and copyEntries'
// vouches for missing sources are the two places a warm run used to build a
// fresh resolver per question -- and before that, per pairwise comparison
// -- and their bill arrived together: an already-copied profile whose bytes
// had not changed paid for every recorded entry against every current one,
// on every run.
//
// The profile is warmed once, uncounted. What is counted is what a warm run
// does when there is nothing left to copy: the entries respelled between
// runs in reversed order and in the capitals the volume joins, so no
// recorded entry is answered by the cleaned-spelling set alone and forget
// has to build the stretch's instruments and ask the volume; the sources
// deleted outright, so every entry takes the vouch path instead of the
// copy; and one entry finally dropped from the list, so forget's pass has
// to answer a false, take the copy it leaves behind, and kill the stretch
// whose cached answers the clear has just made into lies. Between the
// counted fills, the same three questions are put to legacyStillNamed and
// legacyRecordVouches -- the old one-resolver-per-pair shape -- over the
// same tree, before that tree is mutated, and their answers are held to the
// new shape's, entry for entry.
//
// The stretch shape's bill is one enumeration of the profile root per
// mutation-free stretch: the stretch's build indexes the names it compares
// against out of one snapshot, and every question after that -- the
// respelled spellings, the rest of the record, the rest of the current list
// -- is answered out of that snapshot, its byName index, its alias book and
// its byCanonical index, whose opens are resolution and not enumeration.
// The opens and reads counters alone cannot tell that shape from the
// per-question one -- each question's own bill looked linear under both --
// so resolutions, children and scans are counted beside them: how many
// spellings were really walked, how many directory children the
// enumerations processed, and how often the alias branch paid its sibling
// scan. The old shape walked both spellings' directories fresh for every
// pair its short-circuits left standing.
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
	// run that used to pay per pair. One stretch of instruments for
	// forget's whole pass -- nothing is cleared, so nothing kills it --
	// and copyEntries reaches for no stretch at all, because every source
	// is still on the volume and the prints skip every file.
	stop := countingResolvers()
	defer stop()
	copied := fill(t, dest)
	resolvers, opens, reads, resolutions, children, scans := stop()
	totalResolvers, totalOpens, totalReads := resolvers, opens, reads
	totalResolutions, totalChildren, totalScans := resolutions, children, scans
	if resolvers != 1 {
		t.Errorf("the warm respelled run built %d resolvers, want one: forget holds one stretch of instruments "+
			"across its whole pass, and copyEntries found every source on the volume and never built one",
			resolvers)
	}
	if opens != 1 || reads != 1 {
		t.Errorf("the warm respelled run opened %d directories and read %d of them, want one of each: the "+
			"stretch enumerated the profile root once at its build, and every question after that -- the "+
			"respelled spellings, the whole record -- is answered out of that snapshot's byName index and alias "+
			"book, whose opens are resolution and not enumeration", opens, reads)
	}
	if resolutions != 12 {
		t.Errorf("the warm respelled run resolved %d spellings, want twelve: the stretch's build indexed the six "+
			"respelled current places once each, and the six recorded spellings were each resolved once against "+
			"the volume -- every question after a spelling's first is answered from a memo", resolutions)
	}
	if children != 6 {
		t.Errorf("the warm respelled run's one enumeration processed %d children, want six -- the profile "+
			"root's own entries, counted once for the whole pass where the per-question shape counted them "+
			"six times over", children)
	}
	if scans != 1 {
		t.Errorf("the warm respelled run scanned the profile root's siblings %d times, want one: the first "+
			"respelled spelling's scan filled the snapshot's byCanonical index, and the five after it read the "+
			"index instead of scanning again", scans)
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

	// Phase 3, every source gone: forget's questions are all answered by
	// the cleaned-spelling set -- the record follows the rules spellings
	// after the last run -- so it builds nothing at all, and copyEntries
	// builds one stretch for all six vouches, no mirror falling between
	// them because there is nothing left to copy.
	stop = countingResolvers()
	copied = fill(t, dest)
	resolvers, opens, reads, resolutions, children, scans = stop()
	totalResolvers, totalOpens, totalReads = totalResolvers+resolvers, totalOpens+opens, totalReads+reads
	totalResolutions, totalChildren, totalScans = totalResolutions+resolutions, totalChildren+children, totalScans+scans
	if resolvers != 1 {
		t.Errorf("the run with every source gone built %d resolvers, want one: forget answered every recorded "+
			"entry out of the cleaned-spelling set without building anything, and copyEntries built one stretch "+
			"of instruments for all six vouches", resolvers)
	}
	if opens != 1 || reads != 1 {
		t.Errorf("the run with every source gone opened %d directories and read %d of them, want one of each: "+
			"the vouch stretch enumerated the profile root once at its build, and every vouch after that is "+
			"membership in the set the build collected", opens, reads)
	}
	if resolutions != 6 {
		t.Errorf("the run with every source gone resolved %d spellings, want six: the record's six places, "+
			"indexed once at the stretch's build; the six vouches themselves are cache hits, the vouched "+
			"spelling being one the build indexed", resolutions)
	}
	if children != 6 {
		t.Errorf("the run with every source gone's one enumeration processed %d children, want six -- the "+
			"profile root's own entries, once for all six vouches instead of once per question", children)
	}
	if scans != 1 {
		t.Errorf("the run with every source gone scanned the profile root's siblings %d times, want one: the "+
			"first respelled record spelling's scan filled the snapshot's index, and the five after it read it", scans)
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
	resolvers, opens, reads, resolutions, children, scans = stop()
	totalResolvers, totalOpens, totalReads = totalResolvers+resolvers, totalOpens+opens, totalReads+reads
	totalResolutions, totalChildren, totalScans = totalResolutions+resolutions, totalChildren+children, totalScans+scans
	if resolvers != 2 {
		t.Errorf("the run that dropped an entry built %d resolvers, want two: forget's stretch, killed by the "+
			"real clear of the entry the list dropped, and the fresh one copyEntries built for the vouches the "+
			"sources still gone ask for", resolvers)
	}
	if opens != 2 || reads != 2 {
		t.Errorf("the run that dropped an entry opened %d directories and read %d of them, want two of each: "+
			"one enumeration of the profile root before the clear, for forget's stretch, and one after it, for "+
			"the vouch stretch -- the second stretch cannot read the first's snapshot, because the clear took "+
			"the entry it described out of the directory", opens, reads)
	}
	if resolutions != 12 {
		t.Errorf("the run that dropped an entry resolved %d spellings, want twelve: forget's stretch indexed "+
			"the five shortened current places and asked the volume once about the recorded entry they stopped "+
			"naming, and the vouch stretch indexed the six-entry record", resolutions)
	}
	if children != 11 {
		t.Errorf("the run that dropped an entry's two enumerations processed %d children, want eleven -- six "+
			"before the clear, five after it, the profile root's own count shrinking with the entry the clear "+
			"took", children)
	}
	if scans != 2 {
		t.Errorf("the run that dropped an entry scanned the profile root's siblings %d times, want two -- one "+
			"per stretch, each enumeration needing the scan that fills its index", scans)
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
	// warm runs is four resolvers -- one per mutation-free stretch, and
	// only the run that really clears something pays for a second -- and
	// four enumerations of the profile root, one per stretch, while the
	// pairwise shape re-walked both spellings of every pair its
	// short-circuits left standing -- more than twice as hard at six
	// entries, and the gap grows with the square.
	if totalResolvers != 4 {
		t.Errorf("the three counted runs built %d resolvers, want four: one per mutation-free stretch -- "+
			"forget's whole pass in the warm run, the vouches' in the run with no sources, and a pair in the "+
			"run whose real clear killed forget's stretch midway", totalResolvers)
	}
	if totalOpens != 4 || totalReads != 4 {
		t.Errorf("the three counted runs opened %d directories and read %d of them, want four of each: one "+
			"enumeration of the profile root per stretch, whatever the number of questions the stretch answered",
			totalOpens, totalReads)
	}
	if totalResolutions != 30 {
		t.Errorf("the three counted runs resolved %d spellings, want 30 -- twelve and six and twelve: each "+
			"stretch indexes the names it compares against once and answers each recorded spelling once, "+
			"every question after a spelling's first a cache hit", totalResolutions)
	}
	if totalChildren != 23 {
		t.Errorf("the three counted runs' enumerations processed %d children, want 23 -- six and six and "+
			"eleven: the profile root's entries once per stretch, not once per question", totalChildren)
	}
	if totalScans != 4 {
		t.Errorf("the three counted runs scanned the profile root's siblings %d times, want four -- one per "+
			"stretch: the byCanonical index one scan fills serves every alias question the stretch asks after it",
			totalScans)
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

// TestAWarmForgetCountsChildrenOncePerStretchNotOncePerQuestion is the
// complexity demonstration the review of 2026-09-24 (P2-1) asked for, and
// it counts the thing the opens and reads counters cannot see: the children
// each directory enumeration processes. The warm run where nothing changed
// used to build a fresh resolver per recorded entry, so a pass over the
// record enumerated the profile root once per question and processed the
// root's children once per question -- E times E children over E entries --
// while every question's own opens and reads looked perfectly linear, which
// is why the six-entry test beside this one could not tell the shapes
// apart. The stretch shape enumerates the root once for the whole pass, and
// its one sibling scan serves every respelled spelling in the directory
// through the snapshot's byCanonical index.
func TestAWarmForgetCountsChildrenOncePerStretchNotOncePerQuestion(t *testing.T) {
	if !fileSystemJoins(t, "e0", "E0") {
		t.Skip("this volume holds e0 and E0 apart, so a respelling names a different place and there is nothing to count")
	}
	const k = 8
	names := make([]string, 0, k)
	for i := 0; i < k; i++ {
		names = append(names, fmt.Sprintf("e%d", i))
	}
	// Reversed and capitalized, so no recorded entry is answered by the
	// cleaned-spelling set alone and forget's stretch has to be built and
	// the volume asked about every spelling.
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
	// back [e0..e7], the spellings the questions below are asked about.
	fill(t, dest)

	// The rules file respelled, and the per-question shape's answers and
	// bill for the same eight questions, over the same tree the production
	// run below is measured on. Nothing here mutates -- every recorded
	// entry is still named, so nothing is cleared -- but the questions are
	// put before the run all the same, so both shapes are held to one
	// tree rather than to a tree and its aftermath.
	if err := (&config.Config{Profile: config.Entries(caps)}).Save(); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	var legacy dirCounts
	legacyChildren := 0
	for _, name := range names {
		named, children := legacyPerQuestionStillNamed(root, capsEntries, name, &legacy)
		if !named {
			t.Errorf("the per-question shape said the respelled list no longer names %s, and the run it describes would have cleared a copy the list still names", name)
		}
		legacyChildren += children
	}
	_ = root.Close()
	if legacyChildren != k*k {
		t.Errorf("the per-question shape processed %d children of the profile root across %d questions, want %d -- "+
			"one enumeration of the root's %d children per question, the square the opens and reads counters could not see",
			legacyChildren, k, k*k, k)
	}
	if legacy.opens != k || legacy.reads != k {
		t.Errorf("the per-question shape clocked %d opens and %d reads over %d questions, want %d of each: one "+
			"enumeration of the profile root per question, each bill looking perfectly linear on its own",
			legacy.opens, legacy.reads, k, k)
	}

	// The production run over the same tree, the same eight questions: one
	// stretch of instruments for forget's whole pass, one enumeration of
	// the root shared by every question in it.
	stop := countingResolvers()
	copied := fill(t, dest)
	resolvers, opens, reads, resolutions, children, scans := stop()
	if resolvers != 1 {
		t.Errorf("the warm respelled run built %d resolvers, want one: one stretch of instruments for forget's "+
			"whole pass, and copyEntries found every source on the volume and never built one", resolvers)
	}
	if children != k {
		t.Errorf("the stretch shape processed %d children across the same %d questions, want %d -- one "+
			"enumeration of the profile root for the whole pass, not one per question", children, k, k)
	}
	if resolutions != 2*k {
		t.Errorf("the stretch resolved %d spellings, want %d -- the %d respelled current places indexed once at "+
			"the build and the %d recorded spellings answered once each, every question after a spelling's first "+
			"a cache hit", resolutions, 2*k, k, k)
	}
	if scans != 1 {
		t.Errorf("the alias branch scanned the root's siblings %d times, want one: the first respelled spelling's "+
			"scan filled the snapshot's byCanonical index, and the seven after it read the index instead of "+
			"scanning again", scans)
	}
	if opens != 1 || reads != 1 {
		t.Errorf("the stretch shape opened %d directories and read %d of them, want one of each: the profile "+
			"root, once for the whole pass", opens, reads)
	}
	if legacyChildren <= children {
		t.Errorf("the per-question shape processed %d children against the stretch's %d over the same %d "+
			"questions, and the review's point -- the gap grows with the square -- does not show at K=%d",
			legacyChildren, children, k, k)
	}
	// The certificate that the cheaper shape answers the same: the run
	// cleared nothing, so every copy the per-question shape said was still
	// named survives it, and the record follows the new spellings.
	if !reflect.DeepEqual(pathsOf(copied), caps) {
		t.Errorf("the record came back as %v, want %v: the record follows the new spellings, not the stored ones", pathsOf(copied), caps)
	}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dest, name, "keep.txt")); err != nil {
			t.Errorf("the destination's copy of %s did not survive the run that respelled it in the list: %v", name, err)
		}
	}
}

// TestAliasAnswersAreKeptForTheQuestionsThatFollow reads the resolver's own
// books, because the opens/reads counters cannot see the machinery this
// pins: an alias open is resolution, not enumeration, and is uncounted by
// design. The exact-spelling index and the alias memo are what keep a
// resolver's second question about one spelling from opening anything at
// all -- the first alias query in a directory fills the snapshot's
// sibling-canonical cache and its byCanonical index, and the questions after
// it, the same spelling again or a different spelling of a sibling, read
// those instead of opening the spelling and its siblings again.
func TestAliasAnswersAreKeptForTheQuestionsThatFollow(t *testing.T) {
	if !fileSystemJoins(t, "e5", "E5") {
		t.Skip("this volume holds e5 and E5 apart, so there is no alias answer to keep")
	}
	dest := t.TempDir()
	write(t, filepath.Join(dest, "e5", "x"), "x")
	write(t, filepath.Join(dest, "e5", "y"), "y")
	write(t, filepath.Join(dest, "e6", "z"), "z")

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
	// The sibling scan ran once: the two children of "." have their
	// canonical spellings kept in the snapshot, where the questions after
	// the scan read them.
	snap, ok := resolver.dirs["."]
	if !ok {
		t.Fatal("the root was never snapshotted, so nothing here was measured")
	}
	if len(snap.canonical) != 2 {
		t.Errorf("the sibling scan left %d canonical spellings in the root's snapshot (%v), want two -- e5 and e6, the only children",
			len(snap.canonical), snap.canonical)
	}
	if kept, ok := snap.canonical["e5"]; !ok || kept == "" {
		t.Errorf("the root's snapshot holds %v, and its one child's canonical spelling is missing from it", snap.canonical)
	}
	if _, ok := resolver.dirs["e5"]; !ok {
		t.Error("e5 was never snapshotted, though both comparisons resolved a file inside it")
	}

	// A third comparison through a genuinely different alias spelling, one
	// no earlier question asked about and the alias memo has never heard
	// of: E6. The one sibling scan this resolver ever ran canonicalized
	// both children of the root on its way past, so the snapshot's
	// byCanonical index already holds e6's answer, and the question is
	// served without a second scan -- only the directory the place itself
	// sits in is newly enumerated, because the question genuinely needs
	// its listing.
	if !resolver.samePlace("E6/z", "e6/z") {
		t.Fatal("the third spelling question was answered differently than the first")
	}
	if resolver.scans != 1 {
		t.Errorf("three questions in one directory scanned its siblings %d times, want one: the first scan "+
			"filled the snapshot's byCanonical index, and the questions after it read the index instead of scanning",
			resolver.scans)
	}
	if resolver.opens != 3 || resolver.reads != 3 {
		t.Errorf("three comparisons opened %d directories and read %d of them, want three of each: the root "+
			"and e5 once between the first two questions, e6 once for the third's descent -- and no second "+
			"enumeration of the root anywhere, the third question's alias being answered out of the index",
			resolver.opens, resolver.reads)
	}
	e5Canonical, ok := snap.canonical["e5"]
	if !ok || e5Canonical == "" {
		t.Fatalf("the root's snapshot holds %v, and e5's canonical spelling is missing from it", snap.canonical)
	}
	if got, ok := snap.byCanonical[e5Canonical]; !ok || got.name != "e5" || !got.unique {
		t.Errorf("the root's index holds %v for %s, want the stored name e5 marked unique", got, e5Canonical)
	}
	e6Canonical := snap.canonical["e6"]
	if got, ok := snap.byCanonical[e6Canonical]; !ok || got.name != "e6" || !got.unique {
		t.Errorf("the root's index holds %v for %s, want the stored name e6 marked unique", got, e6Canonical)
	}
}

// TestAScanThatSkippedASiblingDoesNotPoisonTheOnesItKept pins the regression
// the review of 2026-09-25 measured (P2-2): the alias branch's byCanonical
// index can legitimately come out partial, because one sibling's open or
// canonicalization can fail for the moment -- a file behind an exclusive
// handle -- while the rest of the scan succeeds. The retry scan a later
// spelling triggers walks every child again, and the walk it used to extend
// the index in place met the entries its own earlier scan had put there and
// marked each of them not unique: a second observation of one child read as
// a second stored name for one path. The questions after that were refused
// for spellings this same resolver had already resolved -- the false that
// reads, downstream, as "the list no longer names this place", and takes
// the copy.
func TestAScanThatSkippedASiblingDoesNotPoisonTheOnesItKept(t *testing.T) {
	if !fileSystemJoins(t, "b", "B") {
		t.Skip("this volume holds b and B apart, so there is no alias answer to keep")
	}
	dest := t.TempDir()
	write(t, filepath.Join(dest, "a"), "a")
	write(t, filepath.Join(dest, "b"), "b")
	write(t, filepath.Join(dest, "c"), "c")

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	resolver := newPlaceResolver(root)

	// b behind an exclusive handle: share nothing, so the kernel refuses
	// every other open of the file until the handle closes -- the shape
	// of a sibling briefly unavailable to the scan, not gone from the
	// directory.
	locked, err := syscall.UTF16PtrFromString(filepath.Join(dest, "b"))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(locked, syscall.GENERIC_READ, 0, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("the kernel refused the exclusive hold that makes this test's first scan partial: %v", err)
	}

	// The first scan: A resolves, and the scan it triggers is refused b
	// alone. The snapshot keeps what the scan managed -- a and c -- and
	// b has no canonical answer in it yet.
	if !resolver.samePlace("A", "a") {
		t.Fatal("the spelling whose scan was refused the locked sibling did not resolve")
	}
	snap, ok := resolver.dirs["."]
	if !ok {
		t.Fatal("the root was never snapshotted, so nothing here was measured")
	}
	if _, known := snap.canonical["b"]; known {
		t.Errorf("b's canonical spelling entered the snapshot while the exclusive handle held it shut (canonical map: %v)", snap.canonical)
	}
	if _, known := snap.canonical["c"]; !known {
		t.Errorf("the first scan left c out of the snapshot (%v), though nothing held c shut", snap.canonical)
	}

	if err := syscall.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}

	// The retry: B's question finds no answer for b in the index and
	// scans again, past the children the first scan already answered.
	// The second observation of one child must not read as a second
	// name for its path.
	if !resolver.samePlace("B", "b") {
		t.Fatal("the sibling the first scan could not open was never resolved after the handle let go")
	}
	// The question the poisoned index used to refuse: C, resolved by the
	// first scan and present in the index ever since.
	if !resolver.samePlace("C", "c") {
		t.Fatal("the resolver refused a spelling its own earlier scan had resolved, because the retry scan re-met the children it had already answered")
	}
	if resolver.scans != 2 {
		t.Errorf("three questions scanned the root's siblings %d times, want two: the partial first scan, and the retry B's missing answer demanded -- C is answered out of the index the retry rebuilt, not scanned for", resolver.scans)
	}
	for name, canonical := range snap.canonical {
		indexed, ok := snap.byCanonical[canonical]
		if !ok || indexed.name != name || !indexed.unique {
			t.Errorf("the index holds %v for %s (snapshot stores it under %s), want that one stored name, unique", indexed, canonical, name)
		}
	}
	// The measurement's control: a fresh resolver over the same unchanged
	// files answers C, so what failed above was the one resolver's books,
	// never the volume's.
	if !sameEntryPlace(root, "C", "c") {
		t.Fatal("a fresh resolver over the same unchanged files does not resolve C either, so the fixture itself is broken")
	}
}

// TestAMixedWarmCopyKeepsItsStretchAcrossTheMirrorsThatChangedNothing is the
// complexity demonstration the review of 2026-09-25 (P2-1) asked for, and it
// counts the shape the two warm tests beside it cannot meet: a list that
// alternates missing sources with present ones whose bytes have not changed.
// Every present entry's mirror goes through the fingerprint fast-path and
// changes nothing -- no byte moved, no name moved -- and the loop used to
// kill the stretch of instruments after every mirror all the same, so a run
// over E entries half of them missing built E/2 resolvers, enumerated the
// profile root E/2 times and indexed the record E/2 times over -- E/2 full
// indexes of E entries, the square the review measured at four and eight
// entries while openSource was never called once. The mirrors that changed
// no name now end nothing, and the whole run pays for one stretch.
func TestAMixedWarmCopyKeepsItsStretchAcrossTheMirrorsThatChangedNothing(t *testing.T) {
	for _, k := range []int{4, 8} {
		t.Run(fmt.Sprintf("entries=%d", k), func(t *testing.T) {
			names := make([]string, 0, k)
			for i := 0; i < k; i++ {
				names = append(names, fmt.Sprintf("m%d", i))
			}
			home, dest := useProfile(t, names)
			for _, name := range names {
				write(t, filepath.Join(home, name), "abcd")
			}

			// The warming run, uncounted: everything lands, and the
			// record comes back spelled the way the rules file spells
			// it, so forget answers every recorded entry out of the
			// cleaned-spelling set and builds nothing -- the whole
			// counted bill below is copyEntries'.
			fill(t, dest)

			// Half the sources go, every other one, the mixed shape the
			// review measured. The prints the warming run kept still
			// describe every source left standing, so no present entry
			// can be copied: openSource is wired to fail the run if it
			// is ever reached, which makes the control two-sided -- a
			// skip that broke would refuse the fill, not quietly pass.
			for i := 0; i < k; i += 2 {
				if err := os.Remove(filepath.Join(home, names[i])); err != nil {
					t.Fatal(err)
				}
			}
			previous := openSource
			openSource = func(string) (*os.File, error) {
				return nil, fmt.Errorf("a warm run opened a source to copy it, and the skip this test is built on did not happen")
			}
			defer func() { openSource = previous }()

			stop := countingResolvers()
			copied := fill(t, dest)
			resolvers, opens, reads, resolutions, children, scans := stop()

			if resolvers != 1 {
				t.Errorf("the mixed warm run over %d entries built %d resolvers, want one: the missing sources share one stretch of instruments, and the mirrors between them changed no name the stretch describes", k, resolvers)
			}
			if opens != 1 || reads != 1 {
				t.Errorf("the mixed warm run over %d entries opened %d directories and read %d of them, want one of each: the stretch's one indexing of the record enumerates the profile root once", k, opens, reads)
			}
			if resolutions != k {
				t.Errorf("the mixed warm run over %d entries resolved %d spellings, want %d: the record's places, indexed once at the stretch's build, every vouch after that a cache hit", k, resolutions, k)
			}
			if children != k {
				t.Errorf("the mixed warm run over %d entries processed %d children, want %d: one enumeration of the profile root's %d entries for the whole run, where the shape this replaces counted them once per missing source", k, children, k, k)
			}
			if scans != 0 {
				t.Errorf("the mixed warm run scanned the profile root's siblings %d times, want none: every spelling is exact, so no alias branch runs", scans)
			}
			if !reflect.DeepEqual(pathsOf(copied), names) {
				t.Errorf("the record came back as %v, want %v: the entries whose sources went stay vouched for, the entries whose sources stand stay on the list", pathsOf(copied), names)
			}
			for _, name := range names {
				if got := read(t, filepath.Join(dest, name)); got != "abcd" {
					t.Errorf("the destination's copy of %s was disturbed by the run: %q", name, got)
				}
			}
		})
	}
}

// TestARewriteKeepsTheStretchAndACreatedNameEndsIt pins the line the
// stretch now dies on, both sides of it. The source that changed since the
// last run is carried in again -- mirrorFile rewrites the bytes of a file
// that already stood, under the name it already had -- and the stretch the
// missing sources share must survive it: no listing and no canonical answer
// describes bytes. The destination that lost a file is made whole again by
// the same mirrorFile, and that one is structure: a name made is a listing
// changed, and the stretch dies on it, so the missing source after it asks
// a fresh resolver rather than a cache that watched the profile before the
// name was made. The first half is the fix; the second is the invariant the
// fix must not weaken.
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
	resolvers, opens, reads, resolutions, children, scans := stop()
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
	resolvers, opens, reads, resolutions, children, scans = stop()
	if resolvers != 2 {
		t.Errorf("the run whose mirror made the lost name again built %d resolvers, want two: a name made is structure, the stretch dies on it, and the vouch after it builds fresh instruments", resolvers)
	}
	if opens != 2 || reads != 2 {
		t.Errorf("the create run opened %d directories and read %d of them, want two of each: one indexing before the name was made and one after it", opens, reads)
	}
	if resolutions != 6 {
		t.Errorf("the create run resolved %d spellings, want six: the record's three places indexed once per stretch", resolutions)
	}
	if children != 5 {
		t.Errorf("the create run processed %d children, want five: the root's two entries before the name was made and three after it", children)
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

// TestAClearThatTookNothingBackKeepsTheStretchAndOneThatClearedEndsIt pins
// the same line on the take-back, where clearEntry's own answer is the
// question: stale entries whose copies are already gone from the profile
// answer false, take nothing back, and share one stretch of instruments --
// the shape that used to rebuild after every clear, whatever the clear had
// done -- while a clear that really removed a name ends the stretch, and
// the question after it asks a fresh resolver. forget is called directly,
// with the record and the list a run would hand it, so the counted bill is
// the take-back's alone.
func TestAClearThatTookNothingBackKeepsTheStretchAndOneThatClearedEndsIt(t *testing.T) {
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
	resolvers, opens, reads, resolutions, children, scans := stop()
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
	if got := read(t, filepath.Join(dest, "k0")); got != "kept" {
		t.Errorf("the surviving entry was disturbed by the clears beside it: %q", got)
	}

	// Something taken: b0 and b1 left the list and their copies stand. The
	// first clear removes a real name, the stretch dies on it, and the
	// second question builds a fresh resolver -- two, where the
	// nothing-taken pass above held one. This half is the invariant: a
	// clearEntry that stopped answering true would leave this stretch
	// carrying its answers across a real deletion.
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
	resolvers, opens, reads, resolutions, children, scans = stop()
	_ = root.Close()

	if resolvers != 2 {
		t.Errorf("the pass whose first clear removed a name built %d resolvers, want two: the real clear ends the stretch, and the question after it builds fresh instruments", resolvers)
	}
	if opens != 2 || reads != 2 {
		t.Errorf("the real-clear pass opened %d directories and read %d of them, want two of each: one indexing before the first clear and one after it", opens, reads)
	}
	if resolutions != 4 {
		t.Errorf("the real-clear pass resolved %d spellings, want four: k0 indexed once per stretch, b0 and b1 asked once each", resolutions)
	}
	if children != 5 {
		t.Errorf("the real-clear pass processed %d children, want five: the root's three entries before the first clear and two after it", children)
	}
	if scans != 0 {
		t.Errorf("the real-clear pass scanned the profile root's siblings %d times, want none: every spelling is exact, so no alias branch runs", scans)
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
