package profile

import (
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
		if result := resolver.place(entry.Path); result.ok {
			places[result.canonical] = true
		}
	}
	if !named {
		resolved := resolver.place(recorded)
		named = resolved.ok && places[resolved.canonical]
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
// resolutions and children and scans and visits and canonical maps they
// paid for together.
func countingResolvers() func() (resolvers, opens, reads, resolutions, children, scans, visits, canonicalMaps int) {
	var held []*placeResolver
	previous := newPlaceResolver
	newPlaceResolver = func(root *os.Root) *placeResolver {
		resolver := previous(root)
		held = append(held, resolver)
		return resolver
	}
	return func() (resolvers, opens, reads, resolutions, children, scans, visits, canonicalMaps int) {
		newPlaceResolver = previous
		resolvers = len(held)
		for _, resolver := range held {
			opens += resolver.opens
			reads += resolver.reads
			resolutions += resolver.resolutions
			children += resolver.children
			scans += resolver.scans
			visits += resolver.visits
			canonicalMaps += resolver.canonicalMaps
		}
		held = nil
		return resolvers, opens, reads, resolutions, children, scans, visits, canonicalMaps
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
