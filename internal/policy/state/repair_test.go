// Tests for narrowing a directory already handed over, and for finishing a
// change that was written down and interrupted before it was applied.

package state

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
)

// TestNarrowingADirectoryTakesBackWhatIsInsideIt is the regression guard for a
// refusal that did not reach as far as it promised. A permission set directly
// on a subdirectory is read before a refusal handed down from above it, so
// `grant ~/.config --ro` refused writing in ~/.config while ~/.config/rush,
// handed over separately by the preset, stayed writable.
func TestNarrowingADirectoryTakesBackWhatIsInsideIt(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "tool")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{parent, child} {
		if err := s.Add(dir, grant.RW); err != nil {
			t.Fatal(err)
		}
	}
	allowed, err := access.Check(access.Sandbox{Group: s.SID}, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Allowed {
		t.Fatal("the child was not writable to begin with")
	}

	if err := s.Add(parent, grant.RO); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{parent, child} {
		answer, err := access.Check(access.Sandbox{Group: s.SID}, dir, access.Create)
		if err != nil {
			t.Fatal(err)
		}
		if answer.Allowed {
			t.Errorf("%s is still writable after the directory above it was narrowed: %s",
				dir, answer.Reason)
		}
	}
	if s.Has(child) {
		t.Error("the record still claims a permission that was taken back")
	}
}

// TestNarrowingKeepsTheProjectItself covers a project that happens to sit
// inside a directory being narrowed. It is why the sandbox exists, so it is
// never what a refusal elsewhere takes away.
func TestNarrowingKeepsTheProjectItself(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	project := filepath.Join(parent, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	s.Dir = project
	if err := s.Add(project, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(parent, grant.RO); err != nil {
		t.Fatal(err)
	}
	if !s.Has(project) {
		t.Fatal("the project lost its own permission")
	}
	answer, err := access.Check(access.Sandbox{Group: s.SID}, project, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Allowed {
		t.Errorf("the project directory is no longer writable: %s", answer.Reason)
	}
}

// TestAnInterruptedNarrowingIsFinished is the regression guard for the gap the
// record-first order leaves. A process stopped between writing a change down
// and applying it left a record saying read-only while the entries still said
// writable, and asking for read-only again trusted the record and did nothing,
// so the sandbox went on writing.
func TestAnInterruptedNarrowingIsFinished(t *testing.T) {
	s := newState(t)
	dir := t.TempDir()
	if err := s.Add(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	// What being stopped in the middle leaves behind: the record says
	// read-only and carries the mark, the file system still says writable.
	s.Grants[0].Kind = grant.RO
	s.Grants[0].Pending = true
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	interrupted, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	writable, err := access.Check(access.Sandbox{Group: interrupted.SID}, dir, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !writable.Allowed {
		t.Fatal("the entries were not left writable, so this test proves nothing")
	}

	// Asking for the same thing again has to act rather than trust the record.
	if err := interrupted.Add(dir, grant.RO); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(access.Sandbox{Group: interrupted.SID}, dir, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the sandbox can still write where the record says read-only: %s", answer.Reason)
	}
	if interrupted.Grants[0].Pending {
		t.Error("the change is still marked as unfinished after being applied")
	}
}

// TestFinishPendingRepairsWithoutBeingAsked covers the other way the gap is
// closed: starting a sandbox finishes what an interrupted command began,
// without anyone naming the directory again.
func TestFinishPendingRepairsWithoutBeingAsked(t *testing.T) {
	s := newState(t)
	dir := t.TempDir()
	if err := s.Add(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	s.Grants[0].Kind = grant.RO
	s.Grants[0].Pending = true
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	reread, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	if err := reread.FinishPending(); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(access.Sandbox{Group: reread.SID}, dir, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("an unfinished change was not put right: %s", answer.Reason)
	}
	if reread.Grants[0].Pending {
		t.Error("the mark survived the change being finished")
	}
}

// TestFinishingTwoMarkedChangesDoesNotUndoOneOfThem is the regression guard
// for a repair that walked a copy of the list. Finishing a read-only parent
// takes back what the sandbox holds inside it, and the child was then handed
// out again from a copy made before that happened: gone from the record and
// writable on disk, which is the one state nothing can put right.
func TestFinishingTwoMarkedChangesDoesNotUndoOneOfThem(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "tool")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	// Both marked, the way two interrupted commands would leave them.
	s.Grants = []grant.Spec{
		{Path: parent, Kind: grant.RO, Explicit: true, Pending: true},
		{Path: child, Kind: grant.RW, Pending: true},
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	if err := s.FinishPending(); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(access.Sandbox{Group: s.SID}, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the child is writable after the parent was made read-only: %s", answer.Reason)
	}
	if s.Has(child) != answer.Allowed {
		t.Errorf("the record says %v about the child and Windows says %v",
			s.Has(child), answer.Allowed)
	}
}

// TestAnInterruptedNarrowingKeepsItsMark covers the gap between refusing a
// directory and taking back what is inside it. Settling the change before that
// second half left writable subdirectories under a read-only parent with
// nothing marked, so no later run would notice.
func TestAnInterruptedNarrowingKeepsItsMark(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "tool")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(child, grant.RW); err != nil {
		t.Fatal(err)
	}

	// Stop the narrowing halfway: the parent is refused, the child is not yet
	// taken back, and the change is still marked.
	if err := grant.Apply(s.SID, parent, grant.RO, nil); err != nil {
		t.Fatal(err)
	}
	s.Grants = append(s.Grants, grant.Spec{
		Path: parent, Kind: grant.RO, Explicit: true, Pending: true,
	})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	reread, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	if err := reread.FinishPending(); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(access.Sandbox{Group: reread.SID}, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the child survived the interrupted narrowing: %s", answer.Reason)
	}
}

// TestNarrowingLeavesAChildsOwnRefusalAlone covers what a narrowing must not
// take: an entry inside that already refuses. It never stood in the way, and
// dropping it would cost the directory its own restriction the moment the
// parent was widened again.
func TestNarrowingLeavesAChildsOwnRefusalAlone(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "guarded")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		path string
		kind grant.Kind
	}{{parent, grant.RW}, {child, grant.RO}, {parent, grant.RO}, {parent, grant.RW}} {
		if err := s.Add(step.path, step.kind); err != nil {
			t.Fatal(err)
		}
	}
	if kind, held := s.Kind(child); !held || kind != grant.RO {
		t.Fatalf("the child's own restriction is recorded as %q (held: %v)", kind, held)
	}
	answer, err := access.Check(access.Sandbox{Group: s.SID}, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the child became writable when the parent was widened: %s", answer.Reason)
	}
}

// TestNarrowingFinishesAChildsUnappliedRefusal is the regression guard for an
// entry that was passed over on the strength of what the record said. A
// refusal inside the directory never stood in the way of the refusal from
// above, so narrowing skipped it — even when that refusal had been written
// down and never applied, which leaves the sandbox writing there while the
// narrowing reports success.
func TestNarrowingFinishesAChildsUnappliedRefusal(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "guarded")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(child, grant.RW); err != nil {
		t.Fatal(err)
	}
	// What an interrupted narrowing of the child leaves: the record says
	// read-only and carries the mark, the entries still allow writing.
	index, _ := s.find(child)
	s.Grants[index].Kind = grant.RO
	s.Grants[index].Pending = true
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	writable, err := access.Check(access.Sandbox{Group: s.SID}, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !writable.Allowed {
		t.Fatal("the child was not left writable, so this test proves nothing")
	}

	if err := s.Add(parent, grant.RO); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(access.Sandbox{Group: s.SID}, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the child is still writable after the directory above it was narrowed: %s",
			answer.Reason)
	}
	if kind, held := s.Kind(child); !held || kind != grant.RO {
		t.Errorf("the child's own restriction is recorded as %q (held: %v)", kind, held)
	}
	if index, found := s.find(child); found && s.Grants[index].Pending {
		t.Error("the child's change is still marked as unfinished")
	}
}

// TestNarrowingHandlesANestedPendingChildRemovingAGrandchild is the
// regression guard for narrow() acting on a copy of its own list without
// looking each entry up again, the same flaw FinishPending was fixed against
// at its own level. Narrowing a parent can meet a child that is itself
// pending and still writable on disk; finishing that child recurses into
// narrow(child), which removes a grandchild — handed out to the child on its
// own, separately from the parent — from the real record. The outer
// narrow(parent), still working from the snapshot it started with, then tried
// to remove that same grandchild again, found it gone, and failed before the
// parent's own change was ever settled.
func TestNarrowingHandlesANestedPendingChildRemovingAGrandchild(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "child")
	leaf := filepath.Join(child, "leaf")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(child, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(leaf, grant.RW); err != nil {
		t.Fatal(err)
	}
	// What an interrupted narrowing of the child leaves: read-only and marked
	// in the record, still writable on disk.
	index, _ := s.find(child)
	s.Grants[index].Kind = grant.RO
	s.Grants[index].Pending = true
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	if err := s.Add(parent, grant.RO); err != nil {
		t.Fatalf("narrowing the parent failed: %v", err)
	}
	if index, found := s.find(parent); !found || s.Grants[index].Pending {
		t.Error("the parent's own change is still marked as unfinished")
	}
	answer, err := access.Check(access.Sandbox{Group: s.SID}, leaf, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the grandchild is still writable after the parent was narrowed: %s", answer.Reason)
	}
}

// TestNarrowingReachesAGrantUnderAnotherSpellingOfTheSameTree is the
// regression guard for the one path decision in this package that compared
// strings. A subst alias and the name it stands for are one directory to
// Windows and two different strings to an ascii prefix compare, so a grant
// recorded under the alias survived a narrowing made under the real name:
// the record said read-only and the sandbox went on writing. Measured, on a
// real subst drive, before the decision went through the filesystem.
func TestNarrowingReachesAGrantUnderAnotherSpellingOfTheSameTree(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "cache")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := substDrive(t, parent)
	if alias == "" {
		t.Skip("no free drive letter for a subst alias on this machine")
	}
	// Recorded under the alias, narrowed under the real name.
	if err := s.Add(filepath.Join(alias, "cache"), grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(parent, grant.RO); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(access.Sandbox{Group: s.SID}, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the child stayed writable through the spelling the narrowing was not written under: %s", answer.Reason)
	}
	if s.Has(filepath.Join(alias, "cache")) {
		t.Error("the record still claims a permission that was taken back")
	}
}

// substDrive maps a free drive letter to target with subst, the way an
// operator's shell does, and takes the mapping down when the test ends. It
// returns "" when no letter is free.
func substDrive(t *testing.T, target string) string {
	t.Helper()
	for letter := 'D'; letter <= 'Z'; letter++ {
		drive := string(letter) + `:`
		if _, err := os.Stat(drive + `\`); err == nil {
			continue
		}
		if err := exec.Command("cmd", "/c", "subst", drive, target).Run(); err != nil {
			continue
		}
		t.Cleanup(func() {
			_ = exec.Command("cmd", "/c", "subst", drive, "/D").Run()
		})
		return drive
	}
	return ""
}
