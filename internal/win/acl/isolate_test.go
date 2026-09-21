// Tests for handing a directory over: what is narrowed, what is left alone,
// what an absent list counts as, and what a grant that cannot finish leaves
// behind. This is the delete boundary, so most of these are named one by one
// in the build and may never skip.

package acl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/quietexec"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// TestIsolateNarrowsSharedWriteSetOnTheDirectoryItself is the plain case:
// what those two hold on the granted directory is narrowed to reading, and
// never refused outright, because a refusal aimed at either would catch the
// sandbox this grant is for along with everybody else.
func TestIsolateNarrowsSharedWriteSetOnTheDirectoryItself(t *testing.T) {
	dir := t.TempDir()
	writable := []ACE{{Access: AccessModify, Inheritance: InheritObjects | InheritContainers}}
	if err := Set(dir, sid.Everyone, writable); err != nil {
		t.Fatal(err)
	}
	if err := Set(dir, sid.Users, writable); err != nil {
		t.Fatal(err)
	}

	entries := []ACE{{Access: AccessModify, Inheritance: InheritObjects | InheritContainers}}
	if err := Isolate(dir, unusedAccount, entries, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if holds(t, dir, "Everyone", "(M)") {
		t.Error("Everyone still holds Modify after Isolate")
	}
	if holds(t, dir, "Everyone", "(DENY)") {
		t.Error("Isolate refused Everyone instead of narrowing it")
	}
	if !holds(t, dir, "Everyone", "(RX)") {
		t.Error("Everyone lost its reading instead of being narrowed to it")
	}
	// "BUILTIN\Users", not the bare word: "NT AUTHORITY\Authenticated Users"
	// also contains "Users" and would false-positive a substring match.
	if holds(t, dir, `BUILTIN\Users`, "(M)") {
		t.Error("Users still holds Modify after Isolate")
	}
	if !holds(t, dir, `BUILTIN\Users`, "(RX)") {
		t.Error("Users lost its reading instead of being narrowed to it")
	}
	if !holds(t, dir, unusedAccount, "(M)") {
		t.Error("the account this call was for did not get its own grant")
	}
}

// TestIsolateNarrowsSharedWriteHandedDownFromAbove is the regression guard for
// the hole that reopened the whole peer-isolation P0. Replacing what those two
// hold on the granted directory does nothing about an entry a directory above
// hands down, because that entry is a copy belonging to the parent -- and
// Windows adds up every entry that matches, so the granted directory carried a
// read-only one of ours and an inherited writable one, and the writable one
// won the part it covered.
func TestIsolateNarrowsSharedWriteHandedDownFromAbove(t *testing.T) {
	parent := t.TempDir()
	if err := Set(parent, sid.Users, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "granted")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Isolate(child, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if holds(t, child, `BUILTIN\Users`, "(M)") {
		t.Error("the write access handed down from the parent survived the grant")
	}
	if !holds(t, child, unusedAccount, "(M)") {
		t.Error("the account this call was for did not get its own grant")
	}
}

// TestIsolateAddsNothingWhereThoseTwoHadNothing keeps narrowing from turning
// into widening. Handing Everyone read access to a directory it could not read
// before would show every account on the machine what is inside, which is the
// opposite of what a grant is for.
func TestIsolateAddsNothingWhereThoseTwoHadNothing(t *testing.T) {
	dir := t.TempDir()
	if err := Protect(dir); err != nil {
		t.Fatal(err)
	}
	if holds(t, dir, "Everyone", "") {
		t.Skip("this machine leaves Everyone an entry on a protected directory")
	}
	if err := Isolate(dir, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if holds(t, dir, "Everyone", "") {
		t.Error("Isolate gave Everyone an entry on a directory that had none")
	}
}

// TestIsolateLeavesTheUserAbleToWrite is the regression guard for a grant that
// cost the person making it the directory they were granting: where Users was
// the only thing letting them write, narrowing it took their own access away,
// inside the sandbox and outside it alike.
func TestIsolateLeavesTheUserAbleToWrite(t *testing.T) {
	dir := t.TempDir()
	// Only the crowd, the system and administrators: no entry naming the user.
	if out, err := quietexec.Command("icacls", dir, "/inheritance:r",
		"/grant", "*"+sid.Users+":(OI)(CI)M",
		"/grant", "*S-1-5-18:(OI)(CI)F",
		"/grant", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput(); err != nil {
		t.Skipf("could not arrange a directory the user reaches only through Users: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "before.txt"), []byte("x"), 0o644); err != nil {
		t.Skipf("the user could not write here to begin with: %v", err)
	}

	if err := Isolate(dir, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "after.txt"), []byte("x"), 0o644); err != nil {
		t.Errorf("granting the directory took the user's own write access away: %v", err)
	}
}

// TestAnAuditSeesWhatWasHandedDown is the regression guard for a diagnostic
// that answered about the wrong thing.
//
// Asking whether Everyone may write somewhere was answered from the object's
// own entries alone, so the ordinary shape of the problem — one directory left
// open and everything under it open by inheritance, with not one entry of its
// own — was reported as fine. --audit is what points at the places the
// boundary does not cover, and it was quiet about most of them.
func TestAnAuditSeesWhatWasHandedDown(t *testing.T) {
	root := t.TempDir()
	if err := Set(root, sid.Everyone, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(root, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if !EveryoneWritable(inner) {
		t.Error("a directory inside a world-writable one was reported as not writable by Everyone")
	}
	// And a refusal settles it, the way Windows settles it. The owner is one
	// of Everyone, so this has to come back off before the directory can be
	// taken away again.
	if err := Deny(inner, sid.Everyone, AccessChange); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Remove(inner, sid.Everyone) })
	if EveryoneWritable(inner) {
		t.Error("a refusal was not counted against what was handed down")
	}
}

// TestAGrantThatCannotFinishGrantsNothing is the regression guard for an order
// that could leave a permission in force with nothing pointing at it.
//
// Isolate has two halves: rewriting the directory itself, and sweeping what is
// inside it. The sweep walks a whole tree and can fail anywhere in it — here on
// an entry of a kind that cannot be carried over, which it refuses rather than
// drop, because dropping one could drop a refusal. Rewriting the directory
// first meant such a failure left the sandbox holding it while the caller undid
// the record, and a permission the record does not mention can never be found
// again: explain does not list it and revoke does not know about it.

func TestAGrantTakesWriteFromAuthenticatedUsersToo(t *testing.T) {
	root := t.TempDir()
	if err := Set(root, sid.Authenticated, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
	if !writableBy(root, sid.Authenticated) {
		t.Fatal("the entry this test is about was not applied, so it is testing nothing")
	}
	if err := Isolate(root, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if writableBy(root, sid.Authenticated) {
		t.Error("handing the directory over left Authenticated Users able to change it, " +
			"which is every other sandbox on the machine")
	}
	// And the owner keeps what that entry was giving them, the same as for
	// the other two: a grant must not cost somebody the directory they were
	// granting.
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	if !writableBy(root, owner) {
		t.Error("the person granting the directory lost their own write to it")
	}
}
