package acl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

func TestUnderSkippedUsesFilesystemSpelling(t *testing.T) {
	root := `C:\tree\K`
	if !underSkipped(root+`\child`, root) {
		t.Fatal("a descendant of a skipped directory was not recognized")
	}
	if underSkipped(`C:\tree\`+"K"+`\child`, root) {
		t.Fatal("a Unicode-distinct sibling was treated as a skipped descendant")
	}
	if underSkipped(root+`2`, root) {
		t.Fatal("a name with the skipped directory as a prefix was treated as a descendant")
	}
}

// TestTheOwnerDecisionHappensBeforeTheDescriptorIsFreed is the close test
// of the order the readable contract states: the owner question is answered
// while the descriptor it came from is still allocated, and the answer that
// comes back is the one answered there. The seam stands between the
// comparison and the free that follows it and returns a decision that is
// not the truth -- so the only way readable can come out agreeing with the
// seam is for the decision to have been made inside its own descriptor's
// lifetime, the one stretch of road the borrowed pointer used to be carried
// across.
func TestTheOwnerDecisionHappensBeforeTheDescriptorIsFreed(t *testing.T) {
	file := filepath.Join(t.TempDir(), "owned.txt")
	if err := os.WriteFile(file, []byte("owned"), 0o644); err != nil {
		t.Fatal(err)
	}
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, file, owner)
	pointer, err := sid.Parse(owner)
	if err != nil {
		t.Fatal(err)
	}
	name, err := sid.Name(pointer)
	if err != nil {
		t.Fatal(err)
	}
	// A stranger's identity list, so the real answer about this file is no.
	stranger, err := sid.Parse(unusedAccount)
	if err != nil {
		t.Fatal(err)
	}

	decided := 0
	seen := ""
	real := ownerDecision
	ownerDecision = func(owner uintptr, _ []uintptr) bool {
		decided++
		// The owner is a borrowed pointer into the descriptor's memory, and
		// this is its one moment of validity: it must still name the
		// account it named when the descriptor was read.
		seen, err = sid.Name(owner)
		if err != nil {
			t.Errorf("the owner could not be read back while the decision was being made: %v", err)
			return false
		}
		if seen != name {
			t.Errorf("the owner read back as %q while the decision was being made, want %q", seen, name)
		}
		return true // not the truth -- the decision made inside
	}
	t.Cleanup(func() { ownerDecision = real })

	owned, err := readable(file, []uintptr{stranger})
	if err != nil {
		t.Fatal(err)
	}
	if decided != 1 {
		t.Fatalf("the owner question was answered %d times inside readable, want once", decided)
	}
	if !owned {
		t.Fatal("readable did not return the decision that was made inside its descriptor's lifetime")
	}

	// And with the seam back, the real answer about the same file is no --
	// so the true above came from the seam's decision, not from the list.
	ownerDecision = real
	owned, err = readable(file, []uintptr{stranger})
	if err != nil {
		t.Fatal(err)
	}
	if owned {
		t.Fatal("a file owned by this account came out owned by a stranger's identity list")
	}
}

// TestAPreflightWalkBuildsNoEntryList is the close test of the reading
// pass's two answers: carryable, and whose the object is. Both are answered
// by walking the entries, and neither needs them kept -- the narrowing pass
// reads the list again for itself -- so the walk that used to build one
// slice per object and throw it away builds none.
func TestAPreflightWalkBuildsNoEntryList(t *testing.T) {
	file := filepath.Join(t.TempDir(), "read.txt")
	if err := os.WriteFile(file, []byte("read"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := entrySlices.Load()
	if _, err := readable(file, nil); err != nil {
		t.Fatal(err)
	}
	if got := entrySlices.Load() - before; got != 0 {
		t.Fatalf("the validation pass built %d entry lists to throw away, want none", got)
	}
	// The counter sees what it claims: one real walk of the same list, by
	// the walk that keeps the entries, builds the one slice it is for.
	dacl, descriptor, err := readDACL(file)
	if err != nil {
		t.Fatal(err)
	}
	defer w32.Free(descriptor)
	if dacl == nil {
		t.Fatal("the fixture's list read back as no list at all, so the control proves nothing")
	}
	if _, err := entriesOf(dacl); err != nil {
		t.Fatal(err)
	}
	if got := entrySlices.Load() - before; got != 1 {
		t.Fatalf("one real walk of the list built %d entry lists, want the one it keeps", got)
	}
}
