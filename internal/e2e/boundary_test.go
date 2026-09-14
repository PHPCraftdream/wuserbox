package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// TestDeletingOutsideTheBoundaryIsRefused is the regression guard for the way
// a sandbox could destroy anything its user owned.
//
// A fully restricted token checks every access, deleting included, against
// the sandbox's own restricting identifiers — not only writes, the way a
// write-restricted token's second check did, which left DELETE and
// FILE_DELETE_CHILD answering to the caller's own account instead. By
// Windows' own defaults a user's account holds Full Control all the way down
// their home directory, Full Control included the right to remove things
// inside it whatever they said about themselves, and a write-restricted
// sandbox kept that right wherever the account already had it.
//
// The parent here is given exactly that shape on purpose, rather than
// whatever the machine's temporary directory happens to hand out, so the test
// asks the same question everywhere it runs.
func TestDeletingOutsideTheBoundaryIsRefused(t *testing.T) {
	box := newBox(t)

	outside := filepath.Join(box.root, "not-granted")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	// Owner, system and administrators, with nothing for the sandbox or for
	// Everyone: the shape C:\Users\<name> has by default.
	if err := acl.Protect(outside); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "precious.txt")
	place(t, target, "data")

	mustFail(t, box.state, writeFileCommand(target))
	runSandboxed(t, box.state, []string{"cmd.exe", "/c", "del /q " + target})
	if !exists(target) {
		t.Error("a file outside every granted directory was deleted from inside the sandbox")
	}
}

// TestASweepStopsAtTheBoundary is the same guarantee against the command an
// agent actually reaches for when it goes wrong: a recursive delete over
// everything in sight.
func TestASweepStopsAtTheBoundary(t *testing.T) {
	box := newBox(t)

	outside := filepath.Join(box.root, "not-granted")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := acl.Protect(outside); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(outside, "precious.txt")
	place(t, kept, "data")
	own := filepath.Join(box.granted, "scratch.txt")
	place(t, own, "data")

	runSandboxed(t, box.state, []string{"cmd.exe", "/c", "rmdir /s /q " + box.root})

	if !exists(kept) {
		t.Error("a sweep reached a file outside the sandbox")
	}
	if !exists(outside) {
		t.Error("a sweep removed a directory outside the sandbox")
	}
	if exists(own) {
		t.Error("the project directory should still be the sandbox's to empty")
	}
}

// TestTheSandboxKeepsItsOwnWrites is the other side of the same change: the
// sandbox has to be able to write and delete inside what it was given.
func TestTheSandboxKeepsItsOwnWrites(t *testing.T) {
	box := newBox(t)

	target := filepath.Join(box.granted, "mine.txt")
	mustSucceed(t, box.state, writeFileCommand(target))
	if !exists(target) {
		t.Fatal("the sandbox could not write inside its own project directory")
	}
	runSandboxed(t, box.state, []string{"cmd.exe", "/c", "del /q " + target})
	if exists(target) {
		t.Error("the sandbox could not delete what it had just written")
	}
	// New subdirectories inherit the grant, or the sandbox loses the ability
	// to work inside what it just made.
	nested := filepath.Join(box.granted, "nested")
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "mkdir " + nested})
	mustSucceed(t, box.state, writeFileCommand(filepath.Join(nested, "deep.txt")))
}

// TestReadingIsStillUnrestricted keeps the promise the whole tool is built
// on. A fully restricted token's second check applies to every access, but
// Everyone and BUILTIN\Users still sit in the restricted list to make that
// possible, and grant.Apply only ever narrows either of them to read access,
// never takes reading away — so a sandbox that could no longer read the
// toolchain would be useless.
func TestReadingIsStillUnrestricted(t *testing.T) {
	box := newBox(t)

	outside := filepath.Join(box.root, "readable")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "notes.txt")
	place(t, target, "readable")
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "type " + target})
}

// TestRevokingTakesTheDeleteBackToo is the regression guard for a permission
// that was revoked in name only. Deleting goes through the sandbox's own
// restricting identifier now, the same as any other access, so taking that
// identifier's entry away has to take the delete right with it.
func TestRevokingTakesTheDeleteBackToo(t *testing.T) {
	b := newBox(t)
	extra := filepath.Join(b.root, "extra")
	if err := os.Mkdir(extra, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.state.Add(extra, grant.RW); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(extra, "f.txt")
	place(t, target, "data")
	if err := b.state.Remove(extra); err != nil {
		t.Fatal(err)
	}

	runSandboxed(t, b.state, []string{"cmd.exe", "/c", "del /q " + target})
	if !exists(target) {
		t.Error("the sandbox deleted inside a directory it no longer holds")
	}
}

// TestNarrowingToReadOnlyTakesTheDeleteBackToo is the same guarantee for the
// other way a permission is taken away. Read-only that still lets the
// directory be emptied is not read-only.
func TestNarrowingToReadOnlyTakesTheDeleteBackToo(t *testing.T) {
	b := newBox(t)
	narrowed := filepath.Join(b.root, "narrowed")
	if err := os.Mkdir(narrowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.state.Add(narrowed, grant.RW); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(narrowed, "f.txt")
	place(t, target, "data")
	if err := b.state.Add(narrowed, grant.RO); err != nil {
		t.Fatal(err)
	}

	runSandboxed(t, b.state, []string{"cmd.exe", "/c", "del /q " + target})
	if !exists(target) {
		t.Error("the sandbox emptied a directory it holds read-only")
	}
}

// TestTheDiagnosticAgreesWithWhatHappens pairs every answer --check gives
// with the operation itself, deleting included: a fully restricted token
// applies the same two checks to every access, so --check's simulation and a
// real delete now agree the way they already did for every other operation —
// unlike a write-restricted token, whose second check never applied to
// deleting at all, which used to make a delete refusal from the simulation
// unusable as an answer.
//
// An answer that disagrees with the result is worse than no answer: it is the
// tool certifying a boundary it does not have, and somebody deciding what to
// hand over on the strength of it.
func TestTheDiagnosticAgreesWithWhatHappens(t *testing.T) {
	b := newBox(t)

	outside := filepath.Join(b.root, "not-granted")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := acl.Protect(outside); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		filepath.Join(b.granted, "mine.txt"),
		filepath.Join(outside, "theirs.txt"),
	} {
		place(t, target, "data")
		answer, err := access.Check(b.state.SID, target, access.Delete)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		runSandboxed(t, b.state, []string{"cmd.exe", "/c", "del /q " + target})
		gone := !exists(target)

		if answer.Allowed != gone {
			t.Errorf("%s: --check said deleting is allowed=%v (%s), and the sandbox %s it",
				target, answer.Allowed, answer.Reason,
				map[bool]string{true: "deleted", false: "could not delete"}[gone])
		}
	}
}

// TestOneSandboxCannotDeleteAnothersFiles is the regression guard for the gap
// a fully restricted token alone does not close: every sandbox's restricted
// list carries Everyone and BUILTIN\Users, so it can read the system it needs
// to run anything, and without grant.Apply narrowing either of them on every
// granted directory, any sandbox holding one of those identifiers — every
// sandbox does — could reach what was granted to another.
//
// The shared directory here is given Users:Modify before it is granted, the
// reviewer's mandatory case: an ordinary grant that left inherited access
// like that standing would not close the gap even though it looks closed by
// every test that only checks a sandbox's own directories.
func TestOneSandboxCannotDeleteAnothersFiles(t *testing.T) {
	a, b := newBox(t), newBox(t)
	shared := filepath.Join(b.root, "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := acl.Set(shared, sid.Users, []acl.ACE{
		{Access: acl.AccessModify, Inheritance: acl.InheritObjects | acl.InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.state.Add(shared, grant.RW); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(shared, "b-owns-this.txt")
	place(t, target, "data")

	mustFail(t, a.state, writeFileCommand(target))
	runSandboxed(t, a.state, []string{"cmd.exe", "/c", "del /q " + target})
	if !exists(target) {
		t.Error("one sandbox deleted a file granted to another")
	}
	// Isolating a peer must not cost the owner its own access.
	runSandboxed(t, b.state, []string{"cmd.exe", "/c", "del /q " + target})
	if exists(target) {
		t.Error("isolating a peer also took the owning sandbox's own access away")
	}
}

// TestOneSandboxCannotReachWhatADirectoryAboveHandedDown is the harder half of
// the same guarantee, and the one that reopened this P0 after it was first
// called closed.
//
// Replacing what Everyone and Users hold on the granted directory does nothing
// about an entry a directory *above* it hands down: that entry is a copy
// belonging to the parent, and rewriting this object's list leaves it where it
// is. Windows then adds up every entry that matches, so the granted directory
// carried a read-only entry from the grant and an inherited writable one from
// its parent, and every other sandbox — all of them carry Users — wrote and
// deleted there through the second.
func TestOneSandboxCannotReachWhatADirectoryAboveHandedDown(t *testing.T) {
	a, b := newBox(t), newBox(t)

	parent := filepath.Join(b.root, "parent")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := acl.Set(parent, sid.Users, []acl.ACE{
		{Access: acl.AccessModify, Inheritance: acl.InheritObjects | acl.InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
	// Created under it, so the writable entry arrives by inheritance rather
	// than being set on the directory that is granted.
	shared := filepath.Join(parent, "granted")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.state.Add(shared, grant.RW); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(shared, "b-owns-this.txt")
	place(t, target, "data")

	mustFail(t, a.state, writeFileCommand(filepath.Join(shared, "a-wrote-this.txt")))
	if exists(filepath.Join(shared, "a-wrote-this.txt")) {
		t.Error("one sandbox wrote into a directory granted to another")
	}
	runSandboxed(t, a.state, []string{"cmd.exe", "/c", "del /q " + target})
	if !exists(target) {
		t.Error("one sandbox deleted a file granted to another")
	}
	// And the sandbox it was granted to still has it, as does the user.
	runSandboxed(t, b.state, []string{"cmd.exe", "/c", "del /q " + target})
	if exists(target) {
		t.Error("the owning sandbox lost its own access")
	}
	if err := os.WriteFile(filepath.Join(shared, "user.txt"), []byte("x"), 0o644); err != nil {
		t.Errorf("granting the directory took the user's own write access away: %v", err)
	}
}

// TestAProtectedFileInsideAGrantedDirectorySurvives is the regression guard
// for FILE_DELETE_CHILD. grant.RW's AccessModify does not include it — a
// sandbox's right to delete inside its own directory comes from DELETE on
// each file, inherited from the grant — so a file whose own permissions were
// replaced by acl.Protect, with inheritance switched off, never inherits
// that entry and the directory's own grant cannot reach around it.
func TestAProtectedFileInsideAGrantedDirectorySurvives(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(box.granted, "protected.txt")
	place(t, target, "data")
	if err := acl.Protect(target); err != nil {
		t.Fatal(err)
	}
	mustFail(t, box.state, writeFileCommand(target))
	runSandboxed(t, box.state, []string{"cmd.exe", "/c", "del /q " + target})
	if !exists(target) {
		t.Error("a protected file inside a granted directory was deleted")
	}
}

// TestPeerCannotReachAnEntryASubdirectoryHoldsItself is the regression guard
// for a grant that only rewrote the directory it was given.
//
// Windows hands an inheritable entry down to what is below, but handing it
// down replaces only the handed-down part of a child's list; the child's own
// entries stay as they were. So a directory inside a granted one, carrying an
// entry of its own that let Users write, stayed writable by every other
// sandbox — all of them carry Users — while the directory above it looked
// perfectly isolated.
func TestPeerCannotReachAnEntryASubdirectoryHoldsItself(t *testing.T) {
	a, b := newBox(t), newBox(t)
	tree := filepath.Join(b.root, "tree")
	nested := filepath.Join(tree, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	// Set on the child itself, with inheritance left on, the way an installer
	// leaves a shared directory behind.
	if err := acl.Set(nested, sid.Users, []acl.ACE{
		{Access: acl.AccessModify, Inheritance: acl.InheritObjects | acl.InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.state.Add(tree, grant.RW); err != nil {
		t.Fatal(err)
	}

	intruder := filepath.Join(nested, "a-wrote-this.txt")
	mustFail(t, a.state, writeFileCommand(intruder))
	if exists(intruder) {
		t.Error("a peer wrote inside a granted tree, through an entry the subdirectory held itself")
	}
	// And the sandbox it was granted to still works there.
	own := filepath.Join(nested, "b-wrote-this.txt")
	mustSucceed(t, b.state, writeFileCommand(own))
}

// TestRevokingReachesWhatANestedGrantPinned is the regression guard for a
// revoke that stopped halfway, and the fault was of this tool's own making.
//
// Handing a directory over pins its permission list, copying what it was
// handed from above into its own entries. Where the directory handed over sits
// inside one another sandbox holds, that sandbox's entry is among the copies —
// and a copy answers to nobody, because the directory no longer hears from the
// one above it. Taking the outer grant away left the inner one untouched, so
// the sandbox went on writing in a corner of what it had just lost.
func TestRevokingReachesWhatANestedGrantPinned(t *testing.T) {
	a, b := newBox(t), newBox(t)
	outer := filepath.Join(b.root, "outer")
	inner := filepath.Join(outer, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.state.Add(outer, grant.RW); err != nil {
		t.Fatal(err)
	}
	// Granting the inner one to somebody else is what pins it.
	if err := a.state.Add(inner, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := b.state.Remove(outer); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(inner, "after-revoke.txt")
	mustFail(t, b.state, writeFileCommand(target))
	if exists(target) {
		t.Error("a sandbox wrote inside a directory it had been revoked from")
	}
	// The sandbox the inner directory belongs to is untouched by any of it.
	own := filepath.Join(inner, "still-mine.txt")
	mustSucceed(t, a.state, writeFileCommand(own))
}

// TestASandboxCannotRewriteThePermissionsItWasLeft is the regression guard for
// a right that was not counted as one that changes anything.
//
// Rewriting a permission list is the only right a sandbox needs: with it, it
// hands itself the rest. It was not in the mask that decides what normalising
// takes away, nor in the one --audit reports, so a directory whose entry for
// Everyone was exactly that went through a grant untouched, and a peer used it
// to give Everyone full control and delete the owner's file.
func TestASandboxCannotRewriteThePermissionsItWasLeft(t *testing.T) {
	a, b := newBox(t), newBox(t)
	dir := filepath.Join(b.root, "rewritable")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", dir,
		"/grant", "*"+sid.Everyone+":(OI)(CI)(WDAC)").CombinedOutput(); err != nil {
		t.Fatalf("arranging the directory: %v\n%s", err, out)
	}
	if !acl.EveryoneWritable(dir) {
		t.Error("--audit does not count rewriting the permission list as changing something")
	}
	if err := b.state.Add(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "b-owns-this.txt")
	place(t, victim, "data")

	runSandboxed(t, a.state, []string{"cmd.exe", "/c",
		"icacls " + dir + " /grant *" + sid.Everyone + ":(OI)(CI)F"})
	runSandboxed(t, a.state, []string{"cmd.exe", "/c", "del /q " + victim})
	if !exists(victim) {
		t.Error("a peer rewrote the permissions it was left and deleted another sandbox's file")
	}
}

// TestNarrowingNeverHandsOutReading is the regression guard for a narrowing
// that widened. Replacing what Everyone holds with read-and-execute is only a
// narrowing where reading was already part of it: on an entry that covered
// writing alone, it handed reading to every sandbox and to every account on
// the machine, which is what a grant is least entitled to do.
func TestNarrowingNeverHandsOutReading(t *testing.T) {
	a, b := newBox(t), newBox(t)
	// Outside any box, so nothing hands it an ambient reading permission.
	dir := filepath.Join(t.TempDir(), "write-only")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", dir, "/inheritance:r",
		"/grant", "*"+owner+":(OI)(CI)F",
		"/grant", "*"+sid.System+":(OI)(CI)F",
		"/grant", "*"+sid.Everyone+":(OI)(CI)(WD)").CombinedOutput(); err != nil {
		t.Fatalf("arranging the directory: %v\n%s", err, out)
	}
	secret := filepath.Join(dir, "secret.txt")
	place(t, secret, "classified")
	if runSandboxed(t, a.state, []string{"cmd.exe", "/c", "type " + secret}) == 0 {
		t.Skip("this machine lets a sandbox read there already, so a widening could not be seen")
	}

	if err := b.state.Add(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	if runSandboxed(t, a.state, []string{"cmd.exe", "/c", "type " + secret}) == 0 {
		t.Error("granting the directory handed every sandbox the reading it did not have")
	}
}
