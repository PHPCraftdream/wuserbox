package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

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

func TestCopyRefreshUsesMutationParentInsteadOfMissDependency(t *testing.T) {
	home, dest := useProfile(t, []string{"missingRecord", "parent/nested"})
	write(t, filepath.Join(home, "missingRecord"), "old")
	write(t, filepath.Join(home, "parent", "nested"), "source")
	fill(t, dest)

	if err := os.Remove(filepath.Join(home, "missingRecord")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dest, "missingRecord")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dest, "parent")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dest, "nested"), "locked sibling")
	locked, err := syscall.UTF16PtrFromString(filepath.Join(dest, "nested"))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(locked, syscall.GENERIC_READ, 0, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("locking the unrelated root sibling: %v", err)
	}
	handleOpen := true
	t.Cleanup(func() {
		if handleOpen {
			_ = syscall.CloseHandle(handle)
			handleOpen = false
		}
	})

	previousResolver := newPlaceResolver
	seeded := false
	var measured *placeResolver
	newPlaceResolver = func(root *os.Root) *placeResolver {
		resolver := previousResolver(root)
		measured = resolver
		if !seeded {
			snap, ok := resolver.snapshot(".")
			if !ok {
				t.Fatal("could not snapshot the profile root")
			}
			if _, exists := snap.byName["parent"]; exists {
				t.Fatal("fixture parent existed before the resolver recorded the root listing")
			}
			if err := os.Mkdir(filepath.Join(dest, "parent"), 0o755); err != nil {
				t.Fatal(err)
			}
			seeded = true
		}
		return resolver
	}
	t.Cleanup(func() { newPlaceResolver = previousResolver })

	copied, prints, err := Copy(dest, lastCopied[dest], lastPrints[dest])
	if err != nil {
		t.Fatalf("Copy tried to refresh the root sibling instead of parent/nested: %v", err)
	}
	lastCopied[dest], lastPrints[dest] = copied, prints
	if err := syscall.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	handleOpen = false
	if want := []string{"parent/nested"}; !reflect.DeepEqual(pathsOf(copied), want) {
		t.Fatalf("Copy recorded %v, want %v", pathsOf(copied), want)
	}
	if measured == nil {
		t.Fatal("Copy never built its profile resolver")
	}
	if measured.scans != 1 {
		t.Errorf("the profile resolver scanned %d sibling lists, want only the initial partial scan", measured.scans)
	}
	if _, canonicalized := measured.dirs["."].canonical["nested"]; canonicalized {
		t.Error("the unrelated locked root sibling was canonicalized")
	}
	if got := read(t, filepath.Join(dest, "parent", "nested")); got != "source" {
		t.Fatalf("nested destination contains %q", got)
	}
	if got := read(t, filepath.Join(dest, "nested")); got != "locked sibling" {
		t.Fatalf("unrelated root sibling changed to %q", got)
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
			resolvers, opens, reads, resolutions, children, scans, _ := stop()

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

func TestAMixedCopyRefreshesStructuralMirrorsWithoutReindexingTheRecord(t *testing.T) {
	for _, k := range []int{4, 8} {
		t.Run(fmt.Sprintf("entries=%d", k), func(t *testing.T) {
			names := make([]string, 0, k)
			for i := 0; i < k; i++ {
				names = append(names, fmt.Sprintf("p%d", i))
			}
			home, dest := useProfile(t, names)
			for _, name := range names {
				write(t, filepath.Join(home, name), "same")
			}
			fill(t, dest)

			// Missing sources alternate with mirrors that must recreate a
			// destination name, so every mirror changes structure.
			for i := 0; i < k; i += 2 {
				if err := os.Remove(filepath.Join(home, names[i])); err != nil {
					t.Fatal(err)
				}
			}
			for i := 1; i < k; i += 2 {
				if err := os.Remove(filepath.Join(dest, names[i])); err != nil {
					t.Fatal(err)
				}
			}

			stop := countingResolvers()
			copied := fill(t, dest)
			resolvers, opens, reads, resolutions, children, scans, _ := stop()
			if resolvers != 1 || opens != 1 || reads != 1 || children != k/2 {
				t.Errorf("alternating structural mirrors over %d entries built %d resolvers, opened/read %d/%d directories and processed %d children; want one resolver and one initial index of %d standing entries", k, resolvers, opens, reads, children, k/2)
			}
			if want := 2*k - 1; resolutions != want {
				t.Errorf("the %d-entry mixed run resolved %d spellings, want %d: initial index plus one changed-name refresh and one later vouch per entry", k, resolutions, want)
			}
			if scans > k/2 {
				t.Errorf("the %d-entry refresh scanned %d alias sibling lists, more than one per changed name", k, scans)
			}
			if !reflect.DeepEqual(pathsOf(copied), names) {
				t.Errorf("the record came back as %v, want %v", pathsOf(copied), names)
			}
			for _, name := range names {
				if got := read(t, filepath.Join(dest, name)); got != "same" {
					t.Errorf("destination %s contains %q", name, got)
				}
			}
		})
	}
}

func TestPlaceIndexDoesNotKeepAMissAcrossCreateOrDelete(t *testing.T) {
	dest := t.TempDir()
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	index := newPlaceIndex(root, []string{"created"})
	if index.holds("created") {
		t.Fatal("an absent place was indexed as present")
	}
	write(t, filepath.Join(dest, "created"), "x")
	if err := index.refresh("created"); err != nil {
		t.Fatal(err)
	}
	if !index.holds("created") {
		t.Fatal("the created place remained hidden by the old negative answer")
	}
	if err := os.Remove(filepath.Join(dest, "created")); err != nil {
		t.Fatal(err)
	}
	if err := index.refresh("created"); err != nil {
		t.Fatal(err)
	}
	if index.holds("created") {
		t.Fatal("the removed place remained present in the operation index")
	}

	nested := newPlaceIndex(root, []string{"nested/item"})
	if nested.holds("nested/item") {
		t.Fatal("an absent nested place was indexed as present")
	}
	write(t, filepath.Join(dest, "nested", "item"), "x")
	if err := nested.refresh("nested"); err != nil {
		t.Fatal(err)
	}
	if !nested.holds("nested/item") {
		t.Fatal("creating the missing parent left its cached descendant miss in place")
	}
	if err := os.RemoveAll(filepath.Join(dest, "nested")); err != nil {
		t.Fatal(err)
	}
	if err := nested.refresh("nested"); err != nil {
		t.Fatal(err)
	}
	if nested.holds("nested/item") {
		t.Fatal("removing a parent left its descendant indexed as present")
	}
	if fileSystemJoins(t, "Nested", "nested") {
		cased := newPlaceIndex(root, []string{"nested/item"})
		write(t, filepath.Join(dest, "Nested", "item"), "x")
		if err := cased.refresh("Nested"); err != nil {
			t.Fatal(err)
		}
		if !cased.holds("nested/item") {
			t.Fatal("a case-insensitive creation left the old miss in the index")
		}
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
