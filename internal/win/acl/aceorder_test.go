// The order the entries of a permission list are read in. Windows reads a
// list from the front, and the first entry for an account that names a
// right settles that right: a permission given early is not taken back by
// a refusal behind it, and a refusal ahead of a permission still holds.
// The fixtures here ask the audit question and then put the answer
// against the file system itself, the way a sandbox would meet it:
// creating what the directory may or may not hold.

package acl

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// setSDDLShared writes a permission list without cutting the directory
// above off: the entries the parent hands down survive beside the ones
// this writes, Windows keeping its own order of the two -- an object's
// own entries in front, the inherited ones behind. setSDDL protects, and
// a protected list has nothing handed down to it to sit behind anything.
func setSDDLShared(t *testing.T, path, text string) {
	t.Helper()
	var descriptor uintptr
	if r, _, err := procStringToSecurityDescriptor.Call(uintptr(unsafe.Pointer(w32.UTF16(text))), 1,
		uintptr(unsafe.Pointer(&descriptor)), 0); r == 0 {
		t.Fatalf("building %q: %v", text, err)
	}
	defer w32.Free(descriptor)
	var present, defaulted int32
	var dacl uintptr
	if r, _, err := procGetSecurityDescriptorDacl.Call(descriptor, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		t.Fatalf("reading %q: %v", text, err)
	}
	if r, _, _ := procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, dacl, 0); r != 0 {
		t.Fatalf("setting %s: error %d", path, r)
	}
}

// TestAnEarlyPermissionIsNotTakenBackByTheRefusalBehindIt is the shape the
// audit answered wrongly: a directory whose own permission for Everyone
// comes first, with a refusal for the same identity handed down from above
// sitting behind it -- the order a normal list gives, an object's own
// entries in front of the inherited ones. Windows settles the rights the
// permission names at that permission and never reaches the refusal about
// them, and a plain creation inside succeeds; --audit has to say the same.
func TestAnEarlyPermissionIsNotTakenBackByTheRefusalBehindIt(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	// The refusal is spelled on the directory above, inherit-only, so it
	// applies to nothing there and lands effective on what is under it.
	// The child is already there when the list lands, so the copy it
	// inherits is the one Windows pushes down -- without the inherit-only
	// mark. The child's own permission is written last, and written
	// unprotected, so the inherited refusal is kept behind it.
	setSDDL(t, root, fmt.Sprintf("D:P(D;OICIIO;0x%x;;;WD)", changing))
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setSDDL(t, root, `D:P(A;OICI;FA;;;`+owner+`)`) })
	setSDDLShared(t, child, "D:(A;OICI;FA;;;WD)")

	// The fixture is the finding only if the permission really comes
	// first and the refusal really sits behind it, both effective here.
	dacl, descriptor, err := readDACL(child)
	if err != nil {
		t.Fatal(err)
	}
	defer w32.Free(descriptor)
	held, err := entriesOf(dacl)
	if err != nil {
		t.Fatal(err)
	}
	given, behind := -1, -1
	for i, one := range held {
		if one.access.trustee.form != 0 || one.access.inheritance&InheritOnly != 0 {
			continue
		}
		if one.access.mode == grantAccess && one.access.permissions&changing != 0 && given < 0 {
			given = i
		}
		if one.access.mode == denyAccess && one.access.permissions&changing != 0 {
			behind = i
		}
	}
	if given < 0 || behind < 0 || given > behind {
		t.Fatalf("the fixture is not a permission with an effective refusal behind it: permission at %d, refusal at %d of %d entries", given, behind, len(held))
	}

	pass, err := BeginWritable()
	if err != nil {
		t.Fatal(err)
	}
	everyone, users, err := pass.Writable(child)
	pass.End()
	if err != nil {
		t.Fatal(err)
	}
	if !everyone {
		t.Error("the refusal behind the permission took the permission back: --audit answers unwritable what a creation inside succeeds in")
	}
	if users {
		t.Error("a list that names only Everyone came back writable by BUILTIN\\Users")
	}
	if err := os.WriteFile(filepath.Join(child, "here.txt"), []byte("x"), 0o644); err != nil {
		t.Errorf("creating inside the directory: %v", err)
	}
}

// TestARefusalAheadOfThePermissionStillHolds pins the other order, so the
// fix beside this one is not a forgetting of what a refusal is for: a
// refusal spelled in front of the permission decides the rights it names
// first, and the permission behind it cannot give them back. --audit
// answers unwritable, and the file system agrees.
func TestARefusalAheadOfThePermissionStillHolds(t *testing.T) {
	root := t.TempDir()
	// The refusal covers every changing right, the permission everything
	// there is to give, and the refusal comes first: whatever the
	// permission reaches, the refusal has already settled.
	setSDDL(t, root, fmt.Sprintf("D:P(D;;0x%x;;;WD)(A;OICI;FA;;;WD)", changing))
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setSDDL(t, root, `D:P(A;OICI;FA;;;`+owner+`)`) })

	if EveryoneWritable(root) {
		t.Error("a refusal spelled before the permission was not counted")
	}
	if err := os.WriteFile(filepath.Join(root, "there.txt"), []byte("x"), 0o644); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("creating inside the directory under the early refusal: %v, want permission refused", err)
	}
}

// TestAPartialRefusalAheadOfThePermissionSparesTheBitsItDoesNotName pins
// what a refusal decides when it comes first: only the rights it names,
// only up to where it is reached. A refusal for deleting beside a
// permission for the rest leaves the rest standing -- the directory keeps
// taking new files.
func TestAPartialRefusalAheadOfThePermissionSparesTheBitsItDoesNotName(t *testing.T) {
	dir := t.TempDir()
	// Deleting first, modify behind it: the refusal settles deleting and
	// nothing else, the permission settles the rest.
	setSDDL(t, dir, fmt.Sprintf("D:P(D;;0x10000;;;WD)(A;OICI;0x%x;;;WD)", AccessModify))
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setSDDL(t, dir, `D:P(A;OICI;FA;;;`+owner+`)`) })

	if !EveryoneWritable(dir) {
		t.Error("a refusal for deleting hid the write rights the permission beside it gives")
	}
	if err := os.WriteFile(filepath.Join(dir, "fresh.txt"), []byte("x"), 0o644); err != nil {
		t.Errorf("creating beside a refusal that names only deleting: %v", err)
	}
}
