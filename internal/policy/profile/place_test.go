package profile

import (
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
// other half. stillNamed and recordVouches compare through sameEntryPlace,
// which builds a resolver per comparison, and within one comparison the two
// spellings must not each walk the tree from scratch: the second is asked
// under its own cleaned key and reads nothing the first has not already
// read. One comparison over one place, the second spelling in the capitals
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
