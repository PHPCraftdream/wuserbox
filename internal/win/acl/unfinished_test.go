// What a grant that cannot finish leaves behind, what a sweep costs the
// owner, and what an object with no list at all counts as. Everything here
// is the delete boundary, so most of these are named one by one in the build
// and may never skip.

package acl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

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
	}, InheritObjects|InheritContainers, nil)
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
	}, InheritObjects|InheritContainers, nil); err == nil {
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
	}, InheritObjects|InheritContainers, nil); err != nil {
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
	}, InheritObjects|InheritContainers, nil); err != nil {
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
	}, InheritObjects|InheritContainers, nil); err != nil {
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
