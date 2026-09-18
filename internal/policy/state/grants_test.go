// Tests for what a record holds: recording a permission, replacing it,
// finding it again, and the difference between one somebody asked for and
// one the preset offered.

package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
)

func TestAddRecordsGrantOnceAndPersists(t *testing.T) {
	s := newState(t)
	target := t.TempDir()
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if len(s.Grants) != 1 {
		t.Errorf("grant recorded %d times", len(s.Grants))
	}
	if !s.Has(target) {
		t.Error("Has does not see the grant that was just added")
	}
	stored, err := Load(s.Group)
	if err != nil || stored == nil {
		t.Fatalf("state was not persisted: %v", err)
	}
	if len(stored.Grants) != 1 {
		t.Errorf("persisted grants: %+v", stored.Grants)
	}
}

func TestHasIgnoresCase(t *testing.T) {
	s := newState(t)
	target := t.TempDir()
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if !s.Has(filepath.Clean(target)) {
		t.Error("exact path not found")
	}
	if !s.Has(strings.ToUpper(target)) {
		t.Error("upper-case spelling of the path not found")
	}
	if !s.Has(strings.ToLower(target)) {
		t.Error("lower-case spelling of the path not found")
	}
}

// TestHasDoesNotMergeFilesystemDistinctUnicodePaths is the bookkeeping half
// of the grant boundary: removing a grant by a sibling's Unicode spelling
// must not find or remove the original record.
func TestHasDoesNotMergeFilesystemDistinctUnicodePaths(t *testing.T) {
	parent := t.TempDir()
	latin := filepath.Join(parent, "K")
	kelvin := filepath.Join(parent, "\u212A")
	if err := os.Mkdir(latin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(kelvin, 0o755); err != nil {
		t.Skipf("this volume does not distinguish K and Kelvin sign: %v", err)
	}
	s := newState(t)
	s.Grants = []grant.Spec{{Path: latin, Kind: grant.RW}}
	if s.Has(kelvin) {
		t.Fatal("a filesystem-distinct sibling was treated as the recorded grant")
	}
	if _, found := s.Kind(kelvin); found {
		t.Fatal("Kind found a filesystem-distinct sibling")
	}
}

func TestRemoveDropsTheGrant(t *testing.T) {
	s := newState(t)
	target := t.TempDir()
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(target); err != nil {
		t.Fatal(err)
	}
	if s.Has(target) {
		t.Error("grant survived removal")
	}
	if err := s.Remove(target); err == nil {
		t.Error("removing an unknown grant should be an error")
	}
}

func TestAddReplacesAGrantOfADifferentKind(t *testing.T) {
	s := newState(t)
	target := t.TempDir()
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	// Narrowing the access has to take effect, not be swallowed because the
	// path is already listed.
	if err := s.Add(target, grant.RO); err != nil {
		t.Fatal(err)
	}
	if len(s.Grants) != 1 {
		t.Fatalf("the path was recorded twice: %+v", s.Grants)
	}
	kind, found := s.Kind(target)
	if !found || kind != grant.RO {
		t.Errorf("recorded kind is %q, want %q", kind, grant.RO)
	}
	stored, err := Load(s.Group)
	if err != nil || stored == nil {
		t.Fatalf("state was not persisted: %v", err)
	}
	if stored.Grants[0].Kind != grant.RO {
		t.Errorf("persisted kind is %q", stored.Grants[0].Kind)
	}
	// Widening it again works the same way.
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if kind, _ := s.Kind(target); kind != grant.RW {
		t.Errorf("recorded kind is %q after widening", kind)
	}
}

func TestKindReportsAMissingPath(t *testing.T) {
	s := newState(t)
	if _, found := s.Kind(t.TempDir()); found {
		t.Error("a path that was never granted was reported as recorded")
	}
}

// TestOfferYieldsToWhatSomebodyAskedFor pins the rule the agent preset relies
// on: a permission offered on every start must not undo one that was asked
// for by hand.
func TestOfferYieldsToWhatSomebodyAskedFor(t *testing.T) {
	s := newState(t)
	dir := t.TempDir()
	if err := s.Add(dir, grant.RO); err != nil {
		t.Fatal(err)
	}
	if err := s.Offer(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	if kind, _ := s.Kind(dir); kind != grant.RO {
		t.Errorf("an offer overrode a request: the record says %q", kind)
	}
}

// TestOfferStillFillsInWhatNobodyMentioned keeps an offer doing its work where
// nothing has been said, and keeps it silent about who asked.
func TestOfferStillFillsInWhatNobodyMentioned(t *testing.T) {
	s := newState(t)
	dir := t.TempDir()
	if err := s.Offer(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	if kind, found := s.Kind(dir); !found || kind != grant.RW {
		t.Fatalf("the offer was not recorded: kind %q, found %v", kind, found)
	}
	if s.Grants[0].Explicit {
		t.Error("an offer was recorded as something somebody asked for")
	}

	// Asking for it afterwards makes it a request, and later offers yield.
	if err := s.Add(dir, grant.RO); err != nil {
		t.Fatal(err)
	}
	if !s.Grants[0].Explicit {
		t.Fatal("asking for a directory did not mark it as asked for")
	}
	if err := s.Offer(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	if kind, _ := s.Kind(dir); kind != grant.RO {
		t.Errorf("the record says %q after an offer", kind)
	}
}

// TestARecordFromBeforeTheMarkKeepsItsNarrowing is the regression guard for
// the upgrade itself. The mark that tells a request apart from an offer was
// added to the record, and a file written by an earlier build has none, so
// every permission in it read back as an offer: a directory narrowed by hand
// would have been widened again by the next run of the preset.
func TestARecordFromBeforeTheMarkKeepsItsNarrowing(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	group := "wub-old-record"
	narrowed := t.TempDir()
	old := `{
  "group": "` + group + `",
  "sid": "` + testSID + `",
  "dir": ` + quote(t, t.TempDir()) + `,
  "temp": ` + quote(t, t.TempDir()) + `,
  "grants": [
    {"path": ` + quote(t, narrowed) + `, "kind": "ro"}
  ]
}`
	if err := os.MkdirAll(filepath.Dir(Path(group)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(group), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(group)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Grants[0].Explicit {
		t.Error("a permission from an older record was read as something nobody asked for")
	}
	// What the preset does on the next run must leave it alone.
	if err := loaded.Offer(narrowed, grant.RW); err != nil {
		t.Fatal(err)
	}
	if kind, _ := loaded.Kind(narrowed); kind != grant.RO {
		t.Errorf("the upgrade widened a narrowed directory to %q", kind)
	}
}

// TestAPermissionIsNotHandedOverWhenItCannotBeRecorded is the regression guard
// for an order that could not be undone. The access control entry went on
// first and the record was written second, so a failure to write left a
// directory the sandbox could change that nothing pointed at: explain did not
// list it and revoke could not find it.
func TestAPermissionIsNotHandedOverWhenItCannotBeRecorded(t *testing.T) {
	// The record cannot be written, because the directory it belongs in cannot
	// be created: a file stands where that directory would go.
	inTheWay := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(inTheWay, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCALAPPDATA", inTheWay)

	target := t.TempDir()
	s := &State{Group: "wub-unrecordable", SID: testSID, Dir: t.TempDir(), Temp: t.TempDir()}
	if err := s.Add(target, grant.RW); err == nil {
		t.Fatal("the record could not be written, yet the command reported success")
	}
	if s.Has(target) {
		t.Error("the permission stayed in the record although it was never written")
	}
	answer, err := access.Check(access.Sandbox{Group: s.SID}, target, access.Write)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the directory is writable by a sandbox no record mentions: %s", answer.Reason)
	}
}

// TestOfferManyRecordsAndAppliesEveryDirectory covers the path a sandbox is
// built through: several directories handed over at once, each applied and
// each left in the record with no mark on it.
func TestOfferManyRecordsAndAppliesEveryDirectory(t *testing.T) {
	s := newState(t)
	var specs []grant.Spec
	for i := 0; i < 5; i++ {
		specs = append(specs, grant.Spec{Path: t.TempDir(), Kind: grant.RW})
	}
	if err := s.OfferMany(specs); err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		kind, held := s.Kind(spec.Path)
		if !held || kind != grant.RW {
			t.Errorf("%s came back as %q (held: %v)", spec.Path, kind, held)
		}
		answer, err := access.Check(access.Sandbox{Group: s.SID}, spec.Path, access.Create)
		if err != nil {
			t.Fatal(err)
		}
		if !answer.Allowed {
			t.Errorf("%s was recorded but not applied: %s", spec.Path, answer.Reason)
		}
	}
	for _, held := range s.Grants {
		if held.Pending {
			t.Errorf("%s is still marked as unfinished", held.Path)
		}
	}

	// And the record has to survive being read back by another process.
	reread, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	if len(reread.Grants) != len(specs) {
		t.Errorf("the record holds %d of %d permissions", len(reread.Grants), len(specs))
	}
}

// TestOfferManyYieldsToWhatSomebodyAskedFor keeps the rule that made offers
// different from requests in the first place: doing several at once must not
// quietly widen one that was narrowed by hand.
func TestOfferManyYieldsToWhatSomebodyAskedFor(t *testing.T) {
	s := newState(t)
	narrowed, ordinary := t.TempDir(), t.TempDir()
	if err := s.Add(narrowed, grant.RO); err != nil {
		t.Fatal(err)
	}
	if err := s.OfferMany([]grant.Spec{
		{Path: narrowed, Kind: grant.RW},
		{Path: ordinary, Kind: grant.RW},
	}); err != nil {
		t.Fatal(err)
	}
	if kind, _ := s.Kind(narrowed); kind != grant.RO {
		t.Errorf("an offer overrode a request: the record says %q", kind)
	}
	if kind, _ := s.Kind(ordinary); kind != grant.RW {
		t.Errorf("the other directory was not handed over: %q", kind)
	}
	answer, err := access.Check(access.Sandbox{Group: s.SID}, narrowed, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the narrowed directory became writable: %s", answer.Reason)
	}
}

// TestOfferManyNarrowsOneAtATime covers the kinds it will not take at once.
// Narrowing reaches inside a directory and changes the record as it goes,
// which is not something to do from several threads.
func TestOfferManyNarrowsOneAtATime(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "inside")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Offer(child, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.OfferMany([]grant.Spec{{Path: parent, Kind: grant.RO}}); err != nil {
		t.Fatal(err)
	}
	if s.Has(child) {
		t.Error("narrowing the parent left the entry inside it")
	}
	answer, err := access.Check(access.Sandbox{Group: s.SID}, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the directory inside is still writable: %s", answer.Reason)
	}
}
