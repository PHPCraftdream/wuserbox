package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// These are the counting tests for the take-back half of the review of
// 2026-09-26 (P3-1), docs/reviews/security-performance-review-2026-09-26-round6.md:
// forget's stretch of resolver instruments used to die at the first clear
// that really took a name back, and every real clear after it rebuilt the
// surviving half's place index from the volume -- so a pass that took half
// the record back paid for the keep half once per taken entry, the square
// the review measured. The shape these tests pin retracts instead: each
// real clear takes back exactly the answers it made false, and the stretch
// -- the one build, the presence set, the survivors' resolutions -- outlives
// its own clears.

// TestAForgetThatTakesHalfTheRecordBackRetractsItsAnswersNotRebuilds runs
// the partial take-back the review asked about: a record of k entries, a
// list that keeps the upper half of them under respelled spellings, and
// every recorded entry -- kept or stale -- therefore stale by spelling and
// asked of the volume. The lower half is taken really, each RemoveAll
// landing; the upper half is spared out of the presence set the build
// indexed, the places the clears never touched. The bill is the review's
// point in numbers: one stretch for the whole pass where the replaced shape
// built one per real clear, and one resolution per spelling -- k+k/2 --
// where the replaced shape re-indexed the keep half once per clear.
//
// The opens and reads are not one, and that is the honest part of the
// shape: retract takes back the holding directory's snapshot along with the
// place, so the first question after each clear that has to walk asks the
// root again -- k/2+1 enumerations in all, the children counted shrinking
// as the clears land, k, k-1, and so on down to the keep half. What the
// replaced shape paid per clear was not one enumeration but the whole
// index: every survivor re-resolved, the list re-walked, the square. One
// alias scan serves the pass: the build's first respelled spelling fills
// the snapshot's byCanonical index, and every question after it -- the
// build's own second spelling, and the record's exact matches -- reads an
// index.
func TestAForgetThatTakesHalfTheRecordBackRetractsItsAnswersNotRebuilds(t *testing.T) {
	for _, k := range []int{4, 8} {
		t.Run(fmt.Sprintf("k%d", k), func(t *testing.T) {
			if !fileSystemJoins(t, "e0", "E0") {
				t.Skip("this volume holds e0 and E0 apart, so a respelling names a different place and there is nothing to count")
			}
			names := make([]string, 0, k)
			for i := 0; i < k; i++ {
				names = append(names, fmt.Sprintf("e%d", i))
			}
			// The keep half, respelled in the capitals the volume joins
			// and reversed, so no recorded entry is answered by spelling
			// alone and every one of them is asked of the volume.
			kept := make([]string, 0, k/2)
			for i := k - 1; i >= k/2; i-- {
				kept = append(kept, fmt.Sprintf("E%d", i))
			}

			home, dest := useProfile(t, names)
			for _, name := range names {
				write(t, filepath.Join(home, name, "keep.txt"), "copied")
			}
			// The warming run, uncounted: everything lands and the record
			// comes back [e0..e(k-1)], the spellings the questions below
			// are asked about.
			fill(t, dest)

			if err := (&config.Config{Profile: config.Entries(kept)}).Save(); err != nil {
				t.Fatal(err)
			}
			stop := countingResolvers()
			copied := fill(t, dest)
			resolvers, opens, reads, resolutions, children, scans := stop()

			if resolvers != 1 {
				t.Errorf("the pass that took half the record back built %d resolvers, want one: the real clears retract the answers each made false and the stretch survives them, where the shape the review of 2026-09-26 (P3-1) replaced ended the stretch on the first clear and rebuilt for every clear after it", resolvers)
			}
			if resolutions != k+k/2 {
				t.Errorf("the pass resolved %d spellings, want %d -- the keep half indexed once at the stretch's build and every recorded entry asked of the volume once each, the survivors' resolutions kept through the clears where the replaced shape paid for them once per real clear", resolutions, k+k/2)
			}
			if opens != k/2+1 || reads != k/2+1 {
				t.Errorf("the pass opened %d directories and read %d of them, want %d of each: the stretch's build and one re-ask of the root per real clear, the directory the clear emptied -- retract takes its snapshot back with the place, and the next question that must walk reads what then stands", opens, reads, k/2+1)
			}
			// The children the re-asks process: k at the build, one fewer per
			// landed clear, down to the keep half.
			wantChildren := 0
			for i := 0; i <= k/2; i++ {
				wantChildren += k - i
			}
			if children != wantChildren {
				t.Errorf("the pass processed %d children, want %d -- the root's entries shrinking as the clears land, %d at the build and one fewer each time a name goes, the arithmetic the replaced shape paid twice over plus a whole re-index per clear", children, wantChildren, k)
			}
			if scans != 1 {
				t.Errorf("the alias branch scanned the root's siblings %d times, want one: the build's first respelled spelling filled the snapshot's byCanonical index, and the questions after it -- the second keep spelling and the record's exact matches -- read an index", scans)
			}
			// The certificate that the cheaper shape answers the same: the
			// record follows the new spellings, the taken half is really
			// gone, and the kept half stands.
			if !reflect.DeepEqual(pathsOf(copied), kept) {
				t.Errorf("the record came back as %v, want %v: the record follows the new spellings, not the stored ones", pathsOf(copied), kept)
			}
			for i := 0; i < k; i++ {
				_, err := os.Stat(filepath.Join(dest, fmt.Sprintf("e%d", i), "keep.txt"))
				if i < k/2 && !os.IsNotExist(err) {
					t.Errorf("the lower half's e%d was not taken back: %v", i, err)
				}
				if i >= k/2 && err != nil {
					t.Errorf("the kept e%d did not survive the clears beside it: %v", i, err)
				}
			}
		})
	}
}

// TestAnAliasSpelledStretchSurvivesItsRealClearsByRetraction is the
// invariant the cheaper shape must not weaken: an alias question asked
// after a real clear is put to the volume again, and the alias book's
// answers in the directory the clear changed do not survive it. The
// warming run stores the copies under lowercase names; the middle run --
// uncounted, clearing nothing, copying nothing -- respells the record in
// the capitals the volume joins to them, so every question the counted
// pass asks is an alias question, and the two real clears fall between
// alias questions: E0 and E1 are taken on their answers, and E2 and E3
// are spared by holds against the presence set, each answered after a
// clear out of a fresh enumeration of the directory the clears changed.
// A stretch that kept its alias answers, or its listing, across the
// clears would be answering out of a directory that no longer stands.
func TestAnAliasSpelledStretchSurvivesItsRealClearsByRetraction(t *testing.T) {
	if !fileSystemJoins(t, "e0", "E0") {
		t.Skip("this volume holds e0 and E0 apart, so a respelling names a different place and there is nothing to count")
	}
	home, dest := useProfile(t, []string{"e0", "e1", "e2", "e3"})
	for _, name := range []string{"e0", "e1", "e2", "e3"} {
		write(t, filepath.Join(home, name, "keep.txt"), "copied")
	}
	// The warming run, uncounted: the copies land under the lowercase
	// names the rules file spelled, and the record comes back spelled the
	// same way -- record and stored name agree, and no question below the
	// middle run would go through the alias branch without it.
	fill(t, dest)

	// The middle run, uncounted, respells the rules file -- and with it
	// the record -- in the capitals the volume joins to the stored names:
	// the places are the ones the volume holds, so nothing is cleared and
	// nothing is copied, and the record comes back [E0..E3] over
	// directories still stored under the lowercase names. Every spelling
	// the record now carries is one byName does not hold -- the questions
	// the counted pass asks are alias questions, and two real clears fall
	// between them.
	if err := (&config.Config{Profile: config.Entries([]string{"E0", "E1", "E2", "E3"})}).Save(); err != nil {
		t.Fatal(err)
	}
	copiedMiddle := fill(t, dest)
	if got := pathsOf(copiedMiddle); !reflect.DeepEqual(got, []string{"E0", "E1", "E2", "E3"}) {
		t.Fatalf("the middle run's record came back as %v, want the respelled four: the fixture's alias questions stand on the record wearing the capitals", got)
	}

	// The counted pass: the list keeps half the record in the lowercase
	// the stored names wear, so every recorded spelling is stale by
	// spelling and the volume decides which two name places the list
	// still holds. E0 and E1 are really cleared between alias questions;
	// E2 and E3 are spared by holds against the presence set -- each of
	// them answered after a clear, out of a fresh enumeration of the
	// directory the clears changed.
	if err := (&config.Config{Profile: config.Entries([]string{"e2", "e3"})}).Save(); err != nil {
		t.Fatal(err)
	}
	stop := countingResolvers()
	copied := fill(t, dest)
	resolvers, opens, reads, resolutions, children, scans := stop()

	if resolvers != 1 {
		t.Errorf("the pass whose two real clears sat between alias-spelled questions built %d resolvers, want one: each clear retracts the answers it made false and the stretch -- the presence set with it -- answers the questions after, one stretch across both real clears, the retractions keeping the survivors' index where the replaced shape rebuilt per clear", resolvers)
	}
	if resolutions != 6 {
		t.Errorf("the pass resolved %d spellings, want six: the keep half indexed once at the build and the record's four caps spellings asked once each -- two taken on their answers, two spared by the presence set", resolutions)
	}
	if opens != 3 || reads != 3 {
		t.Errorf("the pass opened %d directories and read %d of them, want three of each: the build, then one re-enumeration of the root after each real clear -- retract takes the holding directory's snapshot back with the place, and the next alias question reads what then stands", opens, reads)
	}
	if children != 9 {
		t.Errorf("the pass processed %d children, want nine: four at the build, three after E0's clear, two after E1's -- the directory shrinking under the questions, not the square the replaced shape paid re-indexing the survivors", children)
	}
	if scans != 3 {
		t.Errorf("the alias branch scanned the root's siblings %d times, want three -- one per fresh enumeration of the directory the clears changed: E0's question scanned the build's listing, E1's and E2's scanned the listings the clears made, and E3 read E2's index", scans)
	}
	if got := pathsOf(copied); !reflect.DeepEqual(got, []string{"e2", "e3"}) {
		t.Errorf("the record came back as %v, want [e2 e3]: the kept half under the spellings the list asked for", got)
	}
	for _, name := range []string{"e0", "e1"} {
		if _, err := os.Stat(filepath.Join(dest, name, "keep.txt")); !os.IsNotExist(err) {
			t.Errorf("the stale %s survived its clear: %v", name, err)
		}
	}
	for _, name := range []string{"e2", "e3"} {
		if got := read(t, filepath.Join(dest, name, "keep.txt")); got != "copied" {
			t.Errorf("the kept %s was disturbed by the clears beside it: %q", name, got)
		}
	}
}

// TestRetractTakesBackExactlyTheAnswersTheClearMadeFalse reads the
// resolver's own books, because the counting tests above see the bill and
// not the retraction that earns it. The review of 2026-09-26 (P3-1),
// docs/reviews/security-performance-review-2026-09-26-round6.md, replaced
// forget's whole-stretch death on a real clear with a scoped one: retract
// drops the taken place's own witnessed answers, and the answers about the
// directory that held it, and keeps the rest. This asks retract directly,
// with no forget around it, over two places of which one goes.
//
// The pins, in order: a spelling the stretch never witnessed is answered
// false -- nothing to scope a retraction to, so the caller ends the
// stretch the old way rather than trust half-cleared instruments. A real
// clear's spelling is answered true, and what it takes back is exact: E0's
// resolution is gone, so the next ask re-walks and finds the volume's
// nothing -- and records that miss, the way every answer is recorded, so
// the ask after it costs nothing and answers the same. E1's resolution is
// not touched -- the survivor's memo answers the next ask without a walk
// -- and the re-read root snapshot carries the survivor and not the taken
// name, with the alias book holding the recorded miss the re-ask left.
func TestRetractTakesBackExactlyTheAnswersTheClearMadeFalse(t *testing.T) {
	if !fileSystemJoins(t, "e0", "E0") {
		t.Skip("this volume holds e0 and E0 apart, so E0 names a different place than e0 and there is nothing to retract")
	}
	dest := t.TempDir()
	write(t, filepath.Join(dest, "e0", "keep.txt"), "taken")
	write(t, filepath.Join(dest, "e1", "keep.txt"), "kept")
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	resolver := newPlaceResolver(root)

	// Two witnessed resolutions, the memos every later question of these
	// spellings reads.
	if canonical, ok := resolver.place("E0"); !ok || canonical != "e0" {
		t.Fatalf("place(E0) answered (%q, %v), want (\"e0\", true): the spelling the stretch must later retract has to be witnessed first", canonical, ok)
	}
	if canonical, ok := resolver.place("E1"); !ok || canonical != "e1" {
		t.Fatalf("place(E1) answered (%q, %v), want (\"e1\", true): the survivor needs a witnessed answer for the retraction to keep", canonical, ok)
	}
	// A spelling the stretch never walked has no answer to take back --
	// forget reads the false as the clear it cannot scope and ends the
	// stretch wholesale, the answer that stays correct whatever the clear
	// did.
	if resolver.retract("EX") {
		t.Errorf("retract(EX) answered true, want false: a spelling the stretch never witnessed has no recorded place to scope the retraction to")
	}

	if err := root.RemoveAll("e0"); err != nil {
		t.Fatal(err)
	}
	if !resolver.retract("E0") {
		t.Errorf("retract(E0) answered false, want true: E0 was witnessed a moment ago, and the clear just made its every answer a lie")
	}
	// The retraction took E0's resolution back, so the next ask is a real
	// walk -- and the volume, asked again, answers nothing, which is
	// recorded the way every answer is.
	if canonical, ok := resolver.place("E0"); ok || canonical != "" {
		t.Errorf("place(E0) after the clear answered (%q, %v), want the volume's nothing: the retraction took the witnessed answer back, so the ask re-walks the directory the clear emptied", canonical, ok)
	}
	// The miss is a memo like any other: the second ask costs the stretch
	// nothing and answers the same nothing.
	if _, ok := resolver.place("E0"); ok {
		t.Errorf("place(E0) answered ok a second time, want the recorded miss: the not-found answer is kept like any other, and a deletion never makes a name the volume once did not have")
	}
	// The survivor's memo is what the retraction was for: E1 costs no
	// walk, and its witnessed answer stands.
	if canonical, ok := resolver.place("E1"); !ok || canonical != "e1" {
		t.Errorf("place(E1) after E0's retraction answered (%q, %v), want (\"e1\", true) from the surviving memo: the clear changed E0 and the directory that held it, and nothing else", canonical, ok)
	}
	if resolver.resolutions != 3 {
		t.Errorf("the resolver counted %d resolutions, want three: E0 and E1 witnessed before the clear, and E0's one re-ask after it -- the second miss and E1's answer are memo hits the retraction kept", resolver.resolutions)
	}

	// The re-read root: the re-ask walked the directory the clear emptied,
	// so its snapshot carries the survivor and not the taken name.
	snap, ok := resolver.dirs["."]
	if !ok {
		t.Fatalf("the resolver holds no snapshot of the root after the re-ask, want the fresh walk the retraction forced")
	}
	if _, ok := snap.byName["e1"]; !ok {
		t.Errorf("the re-read root snapshot does not carry e1, want the survivor the clear never touched")
	}
	if _, ok := snap.byName["e0"]; ok {
		t.Errorf("the re-read root snapshot still carries e0, want the taken name gone from the listing the re-ask walked")
	}
	// And the alias book holds the recorded miss, keyed by the spelling
	// the branch opened: the retraction's own product, kept against the
	// next question of the same spelling.
	miss, ok := resolver.alias[filepath.Join(".", "E0")]
	if !ok {
		t.Errorf("the alias book holds no answer for ./E0, want the recorded miss the re-ask left")
	} else if miss.ok {
		t.Errorf("the alias book's ./E0 answer claims a place at %q, want the recorded miss: the volume answered nothing after the clear", miss.canonical)
	}
}
