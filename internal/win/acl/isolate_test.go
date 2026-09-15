// Tests for handing a directory over: what is narrowed, what is left alone,
// what an absent list counts as, and what a grant that cannot finish leaves
// behind. This is the delete boundary, so most of these are named one by one
// in the build and may never skip.

package acl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

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
	if err := Isolate(dir, unusedAccount, entries, InheritObjects|InheritContainers); err != nil {
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
	}, InheritObjects|InheritContainers); err != nil {
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
	}, InheritObjects|InheritContainers); err != nil {
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
	if out, err := exec.Command("icacls", dir, "/inheritance:r",
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
	}, InheritObjects|InheritContainers); err != nil {
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
func TestAGrantThatCannotFinishGrantsNothing(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	// A conditional entry. Windows stores it as a callback entry, which is one
	// of the kinds this package will not carry over.
	setSDDL(t, child, `D:P(XA;;FA;;;WD;(@USER.Title=="nobody"))`)
	// That list leaves nobody able to remove the directory, this test included.
	// Cleanups run in reverse, so this one puts the owner back before the
	// temporary directory is taken away.
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setSDDL(t, child, `D:P(A;OICI;FA;;;`+owner+`)`) })

	isolateErr := Isolate(root, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers)
	if isolateErr == nil {
		t.Fatal("a grant that could not finish reported success")
	}
	if granted, err := heldBy(root, unusedAccount, AccessModify); err != nil || granted {
		t.Errorf("the grant failed, and the directory was handed over anyway (granted=%v, err=%v)",
			granted, err)
	}
}

// TestAGrantThatCannotFinishChangesNothingAtAll is the second half of the
// guard above. Refusing before the grant is written keeps a permission from
// being in force with nothing pointing at it; refusing before anything is
// written at all keeps the tree as it was found.
//
// The whole tree is read before any of it is changed, so the ordinary reason
// for stopping — an entry of a kind that cannot be carried over — is met while
// nothing has moved. Without that first pass a sibling earlier in the walk was
// already narrowed by the time the bad one was reached, and nothing recorded
// that it had been.
func TestAGrantThatCannotFinishChangesNothingAtAll(t *testing.T) {
	root := t.TempDir()
	// "a" sorts before "z", so the walk reaches it first and would narrow it
	// before meeting the entry it cannot carry.
	early := filepath.Join(root, "a-early")
	late := filepath.Join(root, "z-late")
	for _, dir := range []string{early, late} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := Set(early, sid.Users, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
	if !UsersWritable(early) {
		t.Fatal("the first directory is not writable by Users, so this proves nothing")
	}
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	setSDDL(t, late, `D:P(XA;;FA;;;WD;(@USER.Title=="nobody"))`)
	t.Cleanup(func() { setSDDL(t, late, `D:P(A;OICI;FA;;;`+owner+`)`) })

	if err := Isolate(root, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers); err == nil {
		t.Fatal("a grant that could not finish reported success")
	}

	if !UsersWritable(early) {
		t.Error("a grant that refused had already narrowed part of the tree")
	}
}

// TestASweepDoesNotCostTheOwnerTheirOwnWrite is the regression guard for the
// rule the granted directory already followed, one level down.
//
// Narrowing what Everyone and BUILTIN\Users hold hands whatever it took to the
// owner by name, because those two are not who is being kept out and a grant
// must not cost somebody the directory they were granting. The sweep over what
// is inside left that out, so a directory inside a granted tree that had
// stopped inheriting — one pinned for another sandbox, or one anybody
// protected — whose only write path was Users went read-only to its owner the
// moment the tree above it was handed over.
func TestASweepDoesNotCostTheOwnerTheirOwnWrite(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	// Protected, so nothing above reaches it, and Users is the only writer.
	setSDDL(t, inner, `D:P(A;OICI;0x1301BF;;;BU)(A;OICI;0x1200A9;;;`+owner+`)`)
	t.Cleanup(func() { setSDDL(t, inner, `D:P(A;OICI;FA;;;`+owner+`)`) })

	probe := filepath.Join(inner, "owner.txt")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Fatalf("the owner could not write there to begin with, so this proves nothing: %v", err)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}

	if err := Isolate(root, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Errorf("handing over the tree above cost the owner their own write: %v", err)
	}
	// And the reason for narrowing at all still holds.
	if UsersWritable(inner) {
		t.Error("BUILTIN\\Users still writes inside the granted tree")
	}
}

// TestAGrantDoesNotReachThroughAJunction pins what keeps a grant inside the
// tree it was given.
//
// A junction is an ordinary-looking directory that stands for somewhere else,
// and unlike a symbolic link the walk does not report it as one, so it is not
// skipped for that reason. What makes it safe is measured rather than assumed:
// the walk does not descend into it, because it is not reported as a
// directory either, and reading or writing a permission list by that path
// reaches the junction itself rather than what it points at. Were either to
// change, a grant would quietly rewrite permissions outside everything it was
// handed.
func TestAGrantDoesNotReachThroughAJunction(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writable := []ACE{{Access: AccessModify, Inheritance: InheritObjects | InheritContainers}}
	if err := Set(outside, sid.Users, writable); err != nil {
		t.Fatal(err)
	}
	if err := Set(outside, unusedAccount, writable); err != nil {
		t.Fatal(err)
	}
	beyond := filepath.Join(outside, "beyond.txt")
	if err := os.WriteFile(beyond, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, outside).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a junction: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(link) })

	// Handed to somebody else than the account already named outside, so that
	// what is found there afterwards says which direction it came from. Asking
	// only whether the outside entry survived would pass either way.
	const newcomer = "S-1-5-21-1111111111-2222222222-3333333333-543211"
	if err := Isolate(root, newcomer, writable, InheritObjects|InheritContainers); err != nil {
		t.Fatal(err)
	}
	if !UsersWritable(outside) {
		t.Error("granting a tree narrowed BUILTIN\\Users somewhere outside it, through a junction")
	}
	if kept, err := heldBy(outside, unusedAccount, AccessModify); err != nil || !kept {
		t.Errorf("granting a tree rewrote an entry somewhere outside it, through a junction (kept=%v, err=%v)",
			kept, err)
	}
	// The other half, and the one the comment above has always claimed: a
	// junction must not carry the new permission across either. Nothing removed
	// is only half of "does not reach through".
	if reached, err := heldBy(outside, newcomer, AccessModify); err != nil || reached {
		t.Errorf("granting a tree handed an entry to something outside it, through a junction (reached=%v, err=%v)",
			reached, err)
	}
	if reached, err := heldBy(beyond, newcomer, AccessModify); err != nil || reached {
		t.Errorf("granting a tree reached a file inside the junction's target (reached=%v, err=%v)",
			reached, err)
	}
}

// TestAnObjectWithNoListAtAllIsNarrowedToo is the regression guard for the
// widest an object gets and the one the sweep could not see.
//
// An object with no permission list is not an object with an empty one:
// Windows reads the absence as everybody holding every right. Narrowing works
// through entries, and there were none, so a directory inside a granted tree
// carrying one stayed open to every sandbox on the machine after the tree was
// handed over.
func TestAnObjectWithNoListAtAllIsNarrowedToo(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	setSDDL(t, inner, "D:NO_ACCESS_CONTROL")
	if !EveryoneWritable(inner) {
		t.Fatal("a list-less directory was not writable by Everyone, so this proves nothing")
	}

	if err := Isolate(root, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers); err != nil {
		t.Fatal(err)
	}

	if EveryoneWritable(inner) {
		t.Error("a directory with no permission list is still writable by Everyone")
	}
	if UsersWritable(inner) {
		t.Error("a directory with no permission list is still writable by BUILTIN\\Users")
	}
	// Reading is what the absence gave them, and narrowing never takes away.
	if !holds(t, inner, "Everyone", "(RX)") {
		t.Error("Everyone lost its reading instead of being narrowed to it")
	}
	// The owner still owns it, and so do the two that held it through the same
	// absence a moment ago.
	probe := filepath.Join(inner, "owner.txt")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Errorf("giving the directory a list cost the owner their own write: %v", err)
	}
	for _, who := range []string{"SYSTEM", "Administrators"} {
		if !holds(t, inner, who, "(F)") {
			t.Errorf("%s lost what the missing list had given it", who)
		}
	}
}

// TestGrantingADirectoryWithNoListKeepsItsOwner is the regression guard for
// the same absence one level up.
//
// A directory with no permission list has nothing to carry over, so the grant
// published a list holding the sandbox and nobody else, and the person who
// granted it could no longer write their own directory. What the absence gave
// everybody is written down first, narrowed, and the grant added to that.
func TestGrantingADirectoryWithNoListKeepsItsOwner(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	setSDDL(t, root, "D:NO_ACCESS_CONTROL")
	t.Cleanup(func() { setSDDL(t, root, `D:P(A;OICI;FA;;;`+owner+`)`) })
	if !EveryoneWritable(root) {
		t.Fatal("a list-less directory was not writable by Everyone, so this proves nothing")
	}

	if err := Isolate(root, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "owner.txt"), []byte("x"), 0o644); err != nil {
		t.Errorf("granting a directory with no list cost its owner their own write: %v", err)
	}
	if held, err := heldBy(root, unusedAccount, AccessModify); err != nil || !held {
		t.Errorf("the sandbox did not get what it was granted (held=%v, err=%v)", held, err)
	}
	if EveryoneWritable(root) {
		t.Error("Everyone still writes the directory that was handed over")
	}
	if !holds(t, root, "Everyone", "(RX)") {
		t.Error("Everyone lost its reading instead of being narrowed to it")
	}
}

// TestAGrantRefusesAFileWithASecondNameOutside is the regression guard for the
// one way a grant reached past the tree it named.
//
// A hard link is not a second file, it is a second name for the same one, and
// a permission list belongs to the file rather than to the name. Windows
// propagates the inheritable entry into the file itself, so the name outside
// the granted tree led to a list saying the sandbox may write and delete
// there. Nothing in the sweep asked how many names a file had.
//
// The refusal happens in the reading pass, before anything is written, so a
// tree turned down this way is left exactly as it was found.
func TestAGrantRefusesAFileWithASecondNameOutside(t *testing.T) {
	granted, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "notes.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(granted, "link.txt")
	if out, err := exec.Command("cmd", "/c", "mklink", "/H", link, target).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}

	err := Isolate(granted, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers)
	if err == nil {
		t.Fatal("handed over a tree holding a second name for a file outside it")
	}
	if !strings.Contains(err.Error(), "--allow-links") {
		t.Errorf("the refusal does not say how to go ahead anyway: %v", err)
	}

	if holds(t, target, unusedAccount, "") {
		t.Error("the file outside the tree was reached despite the refusal")
	}
	if holds(t, granted, unusedAccount, "") {
		t.Error("the grant was written despite the refusal, so the tree was left changed")
	}
}

// TestAllowLinksHandsTheTreeOverAnyway is the other half: the refusal above is
// a default and not a wall. Somebody who knows what the links in their tree
// are -- a local git clone, a pnpm store -- says so and the grant goes ahead.
func TestAllowLinksHandsTheTreeOverAnyway(t *testing.T) {
	t.Setenv(EnvAllowLinks, "1")
	granted, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "notes.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(granted, "link.txt")
	if out, err := exec.Command("cmd", "/c", "mklink", "/H", link, target).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}

	if err := Isolate(granted, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers); err != nil {
		t.Fatalf("--allow-links did not let the grant through: %v", err)
	}
	if !holds(t, granted, unusedAccount, "(M)") {
		t.Error("the grant was not written even though links were allowed")
	}
}

// TestAGrantAllowsALinkThatStaysInsideTheTree is the other side of the guard
// above, and the reason it asks where the other name is rather than how many
// there are.
//
// Refusing on any second name refused the ordinary case. Package managers
// deduplicate inside one directory -- two agents under ~/.config sharing one
// copy of a library, one agent's file history sharing a version between
// sessions -- and that is thousands of files in the very directories the
// preset hands over, none of them reaching outside. Measured on a real
// profile, after the strict form made `--init` fail on it.
func TestAGrantAllowsALinkThatStaysInsideTheTree(t *testing.T) {
	granted := t.TempDir()
	first := filepath.Join(granted, "one", "shared.txt")
	if err := os.MkdirAll(filepath.Dir(first), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(granted, "two", "shared.txt")
	if err := os.MkdirAll(filepath.Dir(second), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/H", second, first).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}

	if err := Isolate(granted, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers); err != nil {
		t.Fatalf("a tree whose links all stay inside it was refused: %v", err)
	}
	if !holds(t, granted, unusedAccount, "(M)") {
		t.Error("the grant was not written")
	}
}

// TestALinkInsideATreeNamedInShortFormIsStillInside is the regression guard for
// comparing two spellings of one directory as strings.
//
// A build machine hands out its TEMP in the old eight-and-three form,
// C:\Users\RUNNER~1\..., while the names a file answers to come back spelled
// out, C:\Users\runneradmin\.... The same directory, and not the same string,
// so a tree containing a link to itself was refused as though the link led
// outside. The same would happen to anybody whose path reaches the disk
// through a substituted drive.
func TestALinkInsideATreeNamedInShortFormIsStillInside(t *testing.T) {
	long := filepath.Join(t.TempDir(), "a directory with a long name")
	if err := os.MkdirAll(filepath.Join(long, "one"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(long, "two"), 0o755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(long, "one", "shared.txt")
	if err := os.WriteFile(first, []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(long, "two", "shared.txt")
	if out, err := exec.Command("cmd", "/c", "mklink", "/H", second, first).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}

	short := shortForm(t, long)
	if strings.EqualFold(short, long) {
		t.Skip("this volume does not keep short names, so there is no second spelling to test")
	}

	if err := Isolate(short, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers); err != nil {
		t.Fatalf("a tree named in short form was refused for containing a link to itself: %v", err)
	}
}

// shortForm asks Windows for the eight-and-three spelling of a path.
func shortForm(t *testing.T, path string) string {
	t.Helper()
	wide, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, syscall.MAX_LONG_PATH)
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetShortPathNameW")
	written, _, _ := proc.Call(uintptr(unsafe.Pointer(wide)),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if written == 0 {
		return path
	}
	return syscall.UTF16ToString(buffer[:written])
}
