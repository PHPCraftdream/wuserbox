// The boundary between one sandbox and another: what a peer can reach of
// what this one was handed, what a directory handed over copies into itself
// and stops hearing about, and what taking a grant back has to reach because
// of it. Most of these are named one by one in the build and may never skip.

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/quietexec"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

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
	if out, err := quietexec.Command("icacls", dir,
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

// TestRepairingAnInterruptedNarrowingReachesWhatANestedGrantPinned is the
// regression guard for a repair that came back weaker than the change it was
// repairing.
//
// Narrowing a directory to read-only has two halves: rewriting it, and taking
// this sandbox's entry off what another grant pinned inside it, which no
// longer hears from above. A narrowing made in one go did both. One that was
// interrupted and then finished by FinishPending did only the first, so a
// sandbox stopped at the wrong moment kept writing inside a directory it had
// been narrowed out of — and the record said the change was complete.
func TestRepairingAnInterruptedNarrowingReachesWhatANestedGrantPinned(t *testing.T) {
	a, b := newBox(t), newBox(t)
	outer := filepath.Join(b.root, "outer")
	inner := filepath.Join(outer, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.state.Add(outer, grant.RW); err != nil {
		t.Fatal(err)
	}
	// Granting the inner one to somebody else is what pins it, with b's entry
	// among the copies.
	if err := a.state.Add(inner, grant.RW); err != nil {
		t.Fatal(err)
	}
	// b can write there, which is what the narrowing has to end.
	before := filepath.Join(inner, "before.txt")
	mustSucceed(t, b.state, writeFileCommand(before))

	// The record now says read-only and says it was never finished, which is
	// exactly what an interrupted "wuserbox --grant outer --ro" leaves behind.
	index, found := 0, false
	for i, g := range b.state.Grants {
		if strings.EqualFold(g.Path, outer) {
			index, found = i, true
		}
	}
	if !found {
		t.Fatal("the grant on the outer directory is not in the record")
	}
	b.state.Grants[index].Kind = grant.RO
	b.state.Grants[index].Pending = true
	if err := b.state.Save(); err != nil {
		t.Fatal(err)
	}

	if err := b.state.FinishPending(); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(inner, "after-repair.txt")
	mustFail(t, b.state, writeFileCommand(target))
	if exists(target) {
		t.Error("a repaired narrowing left the sandbox writing inside what it pinned")
	}
	// The sandbox the inner directory belongs to still has it.
	mustSucceed(t, a.state, writeFileCommand(filepath.Join(inner, "still-mine.txt")))
}
