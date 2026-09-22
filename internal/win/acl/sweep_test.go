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

// TestAHandDownNamesTheObjectItLandsOn walks the adapter through the
// inheritance rules it is supposed to reproduce, one measured row at a time:
// a HomeTop deed reaching the files of the granted directory and nothing
// past them, a plain rw grant reaching everything, and the flag shapes in
// between. The entry carries the same rights and the same trustee onto
// whatever the child holds of it; what adapts is the inheritance alone.
func TestAHandDownNamesTheObjectItLandsOn(t *testing.T) {
	trustee, err := sid.Parse(unusedAccount)
	if err != nil {
		t.Fatal(err)
	}
	defer sid.Free(trustee)

	for _, test := range []struct {
		name        string
		inheritance uint32
		generations int
		dir         bool
		want        bool
		flags       uint32
	}{
		// The HomeTop deed: the Modify reaches the files of the granted
		// directory only, and the file the sandbox made holds it effective.
		// A subdirectory holds nothing of it, and neither does anything one
		// generation further -- NO_PROPAGATE was spent on the way there.
		{"home-top modify, file, first generation", InheritObjects | InheritOnly | InheritNoPropagate, 1, false, true, InheritNone},
		{"home-top modify, file, second generation", InheritObjects | InheritOnly | InheritNoPropagate, 2, false, false, 0},
		{"home-top modify, directory, first generation", InheritObjects | InheritOnly | InheritNoPropagate, 1, true, false, 0},
		{"home-top modify, directory, second generation", InheritObjects | InheritOnly | InheritNoPropagate, 2, true, false, 0},
		// The plain rw grant reaches everything at every depth: a file holds
		// it effective, a directory holds it and hands it on unchanged.
		{"rw modify, file, first generation", InheritObjects | InheritContainers, 1, false, true, InheritNone},
		{"rw modify, file, third generation", InheritObjects | InheritContainers, 3, false, true, InheritNone},
		{"rw modify, directory, first generation", InheritObjects | InheritContainers, 1, true, true, InheritObjects | InheritContainers},
		{"rw modify, directory, third generation", InheritObjects | InheritContainers, 3, true, true, InheritObjects | InheritContainers},
		// A files-only entry without NO_PROPAGATE reaches a container as
		// what it is there: inherit-only, for the container's own files.
		{"object-inherit, directory, first generation", InheritObjects, 1, true, true, InheritObjects | InheritOnly},
		{"object-inherit, file, first generation", InheritObjects, 1, false, true, InheritNone},
		// A containers-only entry passes a file by and lands on a directory
		// as it sits.
		{"container-inherit, file, first generation", InheritContainers, 1, false, false, 0},
		{"container-inherit, directory, first generation", InheritContainers, 1, true, true, InheritContainers},
		// INHERIT_ONLY shields only the directory the entry sat on: the child
		// the entry names holds it effective.
		{"container-inherit inherit-only, directory, first generation", InheritContainers | InheritOnly, 1, true, true, InheritContainers},
		// NO_PROPAGATE is spent on the first generation: the child holds the
		// entry effective and nothing below it holds anything at all.
		{"container-inherit no-propagate, directory, first generation", InheritContainers | InheritNoPropagate, 1, true, true, InheritNone},
		{"container-inherit no-propagate, directory, second generation", InheritContainers | InheritNoPropagate, 2, true, false, 0},
		// An entry that reaches nothing inheritable reaches nothing at all:
		// it was written for the directory it sits on alone.
		{"no inheritance, file, first generation", InheritNone, 1, false, false, 0},
		{"no inheritance, directory, first generation", InheritNone, 1, true, false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			one := entry(trustee, AccessModify, test.inheritance, grantAccess)
			got, ok := handDownEntry(one, test.generations, test.dir)
			if ok != test.want {
				t.Fatalf("%s: the child holds the entry: %v, want %v", test.name, ok, test.want)
			}
			if !ok {
				return
			}
			if got.inheritance != test.flags {
				t.Fatalf("%s: the child holds the entry with inheritance %#x, want %#x", test.name, got.inheritance, test.flags)
			}
			if got.permissions != one.permissions || got.mode != one.mode || got.trustee != one.trustee {
				t.Fatalf("%s: the adapted entry changed more than its inheritance", test.name)
			}
		})
	}
}
