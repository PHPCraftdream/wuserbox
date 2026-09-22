// Tests for the operation-local index behind find: that a warm preparation
// pays one resolution per path rather than one per pair, and that the index
// keeps up when the record's path list changes under it.

package state

import (
	"os"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

// asciiUpper respells a path in the capitals the volume joins, the way a
// rules file edited by hand respells one between runs: the same place under
// a string the memo has never heard, which is what makes the asked spelling
// a real question rather than one the build already answered.
func asciiUpper(path string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - ('a' - 'A')
		}
		return r
	}, path)
}

// countingIdentities swaps identityOf for a wrapper that counts every
// resolution the operation really pays for, and hands back the func that
// stops it and reports the total. The real resolver goes back before the
// total is read, so nothing after the counted stretch is measured, and a
// test that dies between an install and its stop leaves the wrapper
// installed answering as the resolver it wrapped, so nothing downstream can
// tell.
func countingIdentities() (stop func() int) {
	held := 0
	previous := identityOf
	identityOf = func(path string) string {
		held++
		return previous(path)
	}
	return func() int {
		identityOf = previous
		return held
	}
}

// recordedGrants hands back a state carrying n explicit read-write grants for
// n resolved temp directories, the shape warm preparation meets on every run:
// the spellings are the ones paths.Resolve normalizes to, nobody has asked
// about any of them yet, and the record has never been written.
func recordedGrants(t *testing.T, n int) (*State, []string) {
	t.Helper()
	s := newState(t)
	dirs := make([]string, n)
	specs := make([]grant.Spec, n)
	for i := range dirs {
		resolved, err := paths.Resolve(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dirs[i] = resolved
		specs[i] = grant.Spec{Path: resolved, Kind: grant.RW, Explicit: true}
	}
	s.Grants = specs
	return s, dirs
}

// TestAWarmPrepareResolvesEachPathOnceNotOncePerPair is the counter the
// review of 2026-09-26 (P3-2) asked for. FromConfig hands one rule path after
// another to Add, and Add used to put the asked spelling through SamePath
// against every recorded grant: one resolution pair per comparison, a stat
// and a file open apiece, before the unchanged fast path could even say
// there was nothing to do. The pairwise loop below is that old shape over
// the same record and the same spellings, and the counted pass is what
// replaced it: one resolution per recorded grant to build the index, one per
// asked path to answer it, and the volume hears nothing more no matter how
// many times the same places are asked about.
func TestAWarmPrepareResolvesEachPathOnceNotOncePerPair(t *testing.T) {
	for _, count := range []int{4, 8} {
		s, dirs := recordedGrants(t, count)

		// The old shape, uncounted by the seam because it is the thing
		// being contrasted: every asked path scans the record until it
		// matches, one SamePath per pair, and every SamePath resolves
		// both of its sides again. The comparisons its short-circuits
		// leave standing come to one plus two plus through count.
		pairs := 0
		for _, asked := range dirs {
			for _, g := range s.Grants {
				pairs++
				if config.SamePath(g.Path, asciiUpper(asked)) {
					break
				}
			}
		}
		wantPairs := count * (count + 1) / 2
		if pairs != wantPairs {
			t.Fatalf("the pairwise scan over %d grants stood on %d comparisons, want %d", count, pairs, wantPairs)
		}

		// The warm pass: one Add per rule path, every one of them
		// unchanged, so no ACL is applied and nothing is saved. The rule
		// paths arrive respelled the way the volume joins, as they do
		// between runs, so each asking is a question of its own.
		stop := countingIdentities()
		for _, asked := range dirs {
			if err := s.Add(asciiUpper(asked), grant.RW); err != nil {
				t.Fatal(err)
			}
		}
		if got := stop(); got != 2*count {
			t.Errorf("warming %d grants against %d rule paths resolved %d keys, want exactly %d: "+
				"one per recorded grant to build the index and one per asked path to answer it, "+
				"not the %d the pairwise shape pays",
				count, count, got, 2*count, 2*wantPairs)
		}

		// The record is untouched, which is what proves the fast path
		// answered before any ACL or save: same entries, same kinds,
		// every mark where it was, and no record file on disk.
		if len(s.Grants) != count {
			t.Fatalf("the warm pass changed the record's length to %d", len(s.Grants))
		}
		for i, held := range s.Grants {
			if held.Path != dirs[i] || held.Kind != grant.RW || !held.Explicit || held.Pending {
				t.Fatalf("the warm pass changed entry %d: %+v", i, held)
			}
		}
		if _, err := os.Stat(Path(s.Group)); !os.IsNotExist(err) {
			t.Errorf("the warm pass wrote a record: %v", err)
		}

		// The same questions once more: the asked spellings are answered
		// from the memo and the recorded places from the index, so the
		// counter must not move at all.
		stop = countingIdentities()
		if err := s.Add(asciiUpper(dirs[0]), grant.RW); err != nil {
			t.Fatal(err)
		}
		if !s.Has(asciiUpper(dirs[count-1])) {
			t.Errorf("the last grant went missing on the second asking")
		}
		if kind, found := s.Kind(asciiUpper(dirs[0])); !found || kind != grant.RW {
			t.Errorf("the first grant reads back as %q (found: %v)", kind, found)
		}
		if got := stop(); got != 0 {
			t.Errorf("re-asking the same paths resolved %d keys, want none: the asked "+
				"spelling is answered from the memo and the recorded places from the index", got)
		}
	}
}

// TestTheIndexKeepsUpWhenTheRecordChanges pins the invalidation. A removal
// shifts every position after the entry it takes out, and an index that
// outlived it would aim the next replacement at where that entry used to be
// -- out of range, or at the wrong grant -- which is the one way the cheap
// answers stop being the same answers.
func TestTheIndexKeepsUpWhenTheRecordChanges(t *testing.T) {
	s, dirs := recordedGrants(t, 3)
	a, b, c := dirs[0], dirs[1], dirs[2]

	// The unchanged question builds the index over [a, b, c].
	if err := s.Add(a, grant.RW); err != nil {
		t.Fatal(err)
	}

	// Taking b away moves c, and the index goes with it.
	if err := s.Remove(b); err != nil {
		t.Fatal(err)
	}
	if s.Has(b) {
		t.Error("a grant survived its removal")
	}
	if !s.Has(a) || !s.Has(c) {
		t.Error("the rebuilt index lost track of the grants that stayed")
	}

	// Narrowing c must replace c where c now sits, not where the stale
	// index would have aimed: the record keeps its length and its order.
	if err := s.Add(c, grant.RO); err != nil {
		t.Fatal(err)
	}
	if len(s.Grants) != 2 {
		t.Fatalf("narrowing c left %d grants, want the same two", len(s.Grants))
	}
	if kind, found := s.Kind(c); !found || kind != grant.RO {
		t.Errorf("c reads back as %q (found: %v), want ro", kind, found)
	}
	if s.Grants[1].Path != c {
		t.Errorf("the replacement landed on %q, not on c where c now sits", s.Grants[1].Path)
	}

	// A path nobody recorded yet is appended, exactly once.
	fresh, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(fresh, grant.RW); err != nil {
		t.Fatal(err)
	}
	if len(s.Grants) != 3 {
		t.Fatalf("the new directory left %d grants, want 3", len(s.Grants))
	}
	if !s.Has(fresh) || s.Grants[2].Path != fresh {
		t.Errorf("the new directory did not land once, at the end: %+v", s.Grants)
	}
}

// TestTheIndexAnswersWhatTheScanAnsweredAboutASpellingTheScanAccepted pins
// that the index's cheap answer is the scan's answer for a non-canonical
// spelling, not just for the one the record itself keeps. A quoted spelling
// is the canonical example of what canonical() is for: Resolve trims it, the
// volume never saw it, and the scan it replaces answered it by resolving
// first and comparing identities second.
func TestTheIndexAnswersWhatTheScanAnsweredAboutASpellingTheScanAccepted(t *testing.T) {
	s, dirs := recordedGrants(t, 1)
	// A quoted spelling is the canonical example of what canonical() is
	// for: Resolve trims it, the volume never saw it, and the scan it
	// replaces answered it by resolving first and comparing identities
	// second. The premise is SamePath's own answer over the same pair.
	quoted := `"` + dirs[0] + `"`
	if !config.SamePath(quoted, dirs[0]) {
		t.Fatal("SamePath does not join the quoted spelling to the recorded grant, so this test proves nothing here")
	}
	if !s.Has(quoted) {
		t.Error("a quoted respelling of a recorded grant no longer finds it")
	}
	if len(s.Grants) != 1 {
		t.Errorf("the quoted spelling recorded a second grant: %+v", s.Grants)
	}
}
