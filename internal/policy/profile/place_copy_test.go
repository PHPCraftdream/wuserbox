package profile

import (
	"fmt"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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
	resolvers, opens, reads, resolutions, children, scans, _, _ := stop()
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
	resolvers, opens, reads, resolutions, children, scans, _, _ = stop()
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
	resolvers, opens, reads, resolutions, children, scans, _, _ = stop()
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
	resolvers, opens, reads, resolutions, children, scans, _, _ := stop()
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

// TestAMultiComponentDirectoryCreationRefreshesItsWholeCreatedChain guards
// the gap the review of 2026-09-29 (round 10, P2-1),
// docs/reviews/security-performance-review-2026-09-29-round10.md, named:
// prepareDir used to mark only dst as the mutation even where MkdirAll made
// several components above it too, unlike file's own missing-parent walk
// for a file's parent chain. The entry here, parent/mid/nested, has its
// whole chain missing on the run that creates it, so a correct refresh has
// to learn that "parent" itself is new, not only that "parent/mid/nested"
// is. A stray file also named "nested" sits at the destination's own root,
// unrelated to the entry and locked exclusively for the length of the
// call, the way the review's own probe staged it: nothing in a correct
// refresh has reason to open it, and the lock turns any open that
// shouldn't happen into a visible failure instead of a quiet one.
func TestAMultiComponentDirectoryCreationRefreshesItsWholeCreatedChain(t *testing.T) {
	home, dest := useProfileEntries(t, []config.Entry{{Path: "anchor"}, {Path: "parent/mid/nested"}})
	write(t, filepath.Join(home, "parent", "mid", "nested", "source"), "copied")
	// anchor's own source is gone; its destination copy stands from an
	// earlier run and the previous record vouches for it.
	write(t, filepath.Join(dest, "anchor"), "from an earlier run")
	write(t, filepath.Join(dest, "nested"), "unrelated to any entry")
	release := lockExclusive(t, filepath.Join(dest, "nested"), false)

	previously := []config.Entry{{Path: "anchor"}, {Path: "parent/mid/nested"}}
	copied, _, err := Copy(dest, previously, nil)
	release()
	if err != nil {
		t.Fatalf("the copy refused over a directory several components deep, reaching for a name it never should have asked about: %v", err)
	}
	if !reflect.DeepEqual(pathsOf(copied), []string{"anchor", "parent/mid/nested"}) {
		t.Errorf("the record came back as %v, want both entries: anchor's destination copy still stands, and parent/mid/nested was just made", pathsOf(copied))
	}
	if got := read(t, filepath.Join(dest, "parent", "mid", "nested", "source")); got != "copied" {
		t.Errorf("the multi-component directory did not land: %q", got)
	}
	if got := read(t, filepath.Join(dest, "nested")); got != "unrelated to any entry" {
		t.Errorf("the stray file sharing the leaf name was disturbed by the unrelated entry's refresh: %q", got)
	}

	// The certificate that the operation-local index agrees with a fresh
	// one built over the same, now-mutated tree: an index left answering a
	// stale question would diverge from this on the very entry the run
	// just made.
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	fresh := newPlaceIndex(root, pathsOf(copied))
	if !fresh.holds("parent/mid/nested") {
		t.Fatal("a fresh index does not hold parent/mid/nested either -- the fixture itself is broken, not the refresh")
	}
}
