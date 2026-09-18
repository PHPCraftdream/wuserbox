// Tests for writing a list onto a path: setting entries, taking them away,
// refusing, and pinning a list so the directory above stops reaching it.
// The two helpers here are shared with the file beside this one, which is
// why they live in the lower of them.

package acl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

const unusedAccount = "S-1-5-21-1111111111-2222222222-3333333333-543210"

// holds reports whether the account appears in the permissions of path, with
// the given text in its entry. An empty text matches any entry.
//
// icacls prints the path itself at the start of the first entry's line, and a
// test name embedded in a temporary directory can spell an account's name by
// accident, so that line has the path taken off it before it is searched.
func holds(t *testing.T, path, account, text string) bool {
	t.Helper()
	out, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v", path, err)
	}
	for i, line := range strings.Split(string(out), "\n") {
		if i == 0 {
			line = strings.TrimPrefix(line, path)
		}
		if strings.Contains(line, account) && strings.Contains(line, text) {
			return true
		}
	}
	return false
}

// setSDDL writes a permission list given in Windows' own text form, which is
// the only way to build entry kinds this package deliberately cannot write.
func setSDDL(t *testing.T, path, text string) {
	t.Helper()
	// CI runners may create temporary files owned by Administrators rather
	// than by the test account. The owner-cap tests model a sandbox whose
	// account owns the object, so make that fixture fact explicit before the
	// descriptor below removes the caller's implicit DACL rights.
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", path, "/setowner", "*"+owner).CombinedOutput(); err != nil {
		// Ordinary local runs often already create these fixtures owned by
		// the caller but cannot exercise /setowner. The admin CI runner can
		// normalize a runner-owned fixture; if it cannot, the owner-specific
		// assertion below fails instead of silently passing.
		t.Logf("could not normalize the fixture owner of %s: %v\n%s", path, err, out)
	}
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
	const protectedDacl = 0x80000000
	if r, _, _ := procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo|protectedDacl, 0, 0, dacl, 0); r != 0 {
		t.Fatalf("setting %s: error %d", path, r)
	}
}

func TestEveryoneWritableSeesAPermission(t *testing.T) {
	dir := t.TempDir()
	if EveryoneWritable(dir) {
		t.Fatalf("a fresh temp directory should not be writable by Everyone: %s", dir)
	}
	if err := Set(dir, sid.Everyone, []ACE{{Access: AccessModify, Inheritance: InheritObjects | InheritContainers}}); err != nil {
		t.Fatal(err)
	}
	if !EveryoneWritable(dir) {
		t.Error("the permission for Everyone was not noticed")
	}
	if err := Remove(dir, sid.Everyone); err != nil {
		t.Fatal(err)
	}
	if EveryoneWritable(dir) {
		t.Error("the permission survived removal")
	}
}

func TestEveryoneWritableIgnoresReadOnlyPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := Set(dir, sid.Everyone, []ACE{{Access: AccessReadExecute, Inheritance: InheritObjects}}); err != nil {
		t.Fatal(err)
	}
	if EveryoneWritable(dir) {
		t.Error("a read-only permission was reported as writable")
	}
}

func TestSetNeedsEntries(t *testing.T) {
	if err := Set(t.TempDir(), unusedAccount, nil); err == nil {
		t.Error("expected an error when no entries are given")
	}
}

func TestSetIsRepeatable(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := Set(dir, unusedAccount, []ACE{{Access: AccessModify, Inheritance: InheritObjects}}); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := Remove(dir, unusedAccount); err != nil {
		t.Fatal(err)
	}
	if err := Remove(dir, unusedAccount); err != nil {
		t.Errorf("removing twice should be harmless: %v", err)
	}
}

func TestCallsReportAMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	if err := Set(missing, unusedAccount, []ACE{{Access: AccessModify}}); err == nil {
		t.Error("Set should fail for a path that does not exist")
	}
	if err := Deny(missing, unusedAccount, AccessModify); err == nil {
		t.Error("Deny should fail for a path that does not exist")
	}
	if err := Protect(missing); err == nil {
		t.Error("Protect should fail for a path that does not exist")
	}
}

func TestCallsRejectNonsenseAccounts(t *testing.T) {
	dir := t.TempDir()
	if err := Set(dir, "not-a-sid", []ACE{{Access: AccessModify}}); err == nil {
		t.Error("Set should reject a malformed account")
	}
	if err := Remove(dir, "not-a-sid"); err == nil {
		t.Error("Remove should reject a malformed account")
	}
}

// TestSetReplacesRefusalsAndNotOnlyPermissions is the regression guard for a
// clearing step that took away permissions and left refusals behind. Windows
// reads a refusal before any permission, so a directory narrowed to read-only
// and then widened again stayed refused by an entry nobody had asked to keep.
func TestSetReplacesRefusalsAndNotOnlyPermissions(t *testing.T) {
	dir := t.TempDir()
	refusal := []ACE{
		{Access: AccessChange, Inheritance: InheritObjects | InheritContainers, Refuse: true},
		{Access: AccessReadExecute, Inheritance: InheritObjects | InheritContainers},
	}
	if err := Set(dir, unusedAccount, refusal); err != nil {
		t.Fatal(err)
	}
	if !holds(t, dir, unusedAccount, "(DENY)") {
		t.Fatal("the refusal was not applied")
	}

	// Widening the account again has to leave nothing of it behind.
	if err := Set(dir, unusedAccount, []ACE{{Access: AccessModify, Inheritance: InheritObjects | InheritContainers}}); err != nil {
		t.Fatal(err)
	}
	if holds(t, dir, unusedAccount, "(DENY)") {
		t.Error("a refusal survived the account being widened")
	}
	if !holds(t, dir, unusedAccount, "(M)") {
		t.Error("the new permission was not applied")
	}
}

func TestRemoveTakesRefusalsAwayToo(t *testing.T) {
	dir := t.TempDir()
	if err := Set(dir, unusedAccount, []ACE{
		{Access: AccessChange, Inheritance: InheritObjects, Refuse: true},
		{Access: AccessReadExecute, Inheritance: InheritObjects},
	}); err != nil {
		t.Fatal(err)
	}
	if err := Remove(dir, unusedAccount); err != nil {
		t.Fatal(err)
	}
	if holds(t, dir, unusedAccount, "") {
		t.Error("the account still holds an entry after being removed")
	}
}

// TestSetReachesTheFileSystemOnce is the regression guard for a replacement
// that published a cleared list first and the real entries second. Between
// those two updates the account held nothing at all, so a directory kept
// read-only inside a writable parent was writable through inheritance for as
// long as the gap lasted, and a sandbox that asked at the right moment could
// create a file there.
func TestSetReachesTheFileSystemOnce(t *testing.T) {
	dir := t.TempDir()
	original := publish
	updates := 0
	publish = func(path string, list []explicitAccess, whole bool) error {
		updates++
		return original(path, list, whole)
	}
	defer func() { publish = original }()

	if err := Set(dir, unusedAccount, []ACE{
		{Access: AccessChange, Inheritance: InheritObjects | InheritContainers, Refuse: true},
		{Access: AccessReadExecute, Inheritance: InheritObjects | InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
	if updates != 1 {
		t.Errorf("the permissions were published %d times, and any number above one "+
			"leaves a moment where the account holds neither the old entries nor the new", updates)
	}
}

// TestListForClearsFirstAndRefusesBeforeItPermits pins the order of the single
// update: the account is replaced, then refused, then permitted. Windows reads
// the finished list in order, so a refusal placed after a permission would
// never be reached.
func TestListForClearsFirstAndRefusesBeforeItPermits(t *testing.T) {
	list := listFor(0, []ACE{
		{Access: AccessReadExecute, Inheritance: InheritObjects},
		{Access: AccessChange, Inheritance: InheritContainers, Refuse: true},
	})
	if len(list) != 3 {
		t.Fatalf("the update has %d entries, want 3", len(list))
	}
	for i, want := range []int32{setAccess, denyAccess, grantAccess} {
		if list[i].mode != want {
			t.Errorf("entry %d is mode %d, want %d", i, list[i].mode, want)
		}
	}
	if list[0].permissions != 0 {
		t.Errorf("the clearing entry asks for %#x, and it should ask for nothing", list[0].permissions)
	}
}

func TestProtectLeavesTheOwnerInControl(t *testing.T) {
	file := filepath.Join(t.TempDir(), "settings.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Protect(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("y"), 0o644); err != nil {
		t.Errorf("the owner lost access to a protected file: %v", err)
	}
	if EveryoneWritable(file) {
		t.Error("a protected file is writable by Everyone")
	}
}

func TestProtectWorksOnDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := Protect(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "child.txt"), []byte("x"), 0o644); err != nil {
		t.Errorf("the owner cannot write inside a protected directory: %v", err)
	}
}

// TestAProtectedObjectInsideAGrantedTreeStaysProtected is a guard against a
// change that would look like a fix.
//
// A protected object does not hear from the directory above it, so handing
// that directory to a sandbox does not reach inside: the sandbox holds the
// tree and not this. It is tempting to call that a gap and have the sweep add
// the sandbox's own identifier to what it normalises — and that would hand
// every granted home directory's .ssh, .aws and .netrc to the sandbox, which
// is the one thing acl.Protect exists to prevent.
//
// The same is true whether the protected object has an ordinary list or none
// at all; the second only looks different because the absence used to give
// everybody everything.
func TestAProtectedObjectInsideAGrantedTreeStaysProtected(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	ordinary := filepath.Join(root, "ordinary")
	listless := filepath.Join(root, "listless")
	for _, dir := range []string{ordinary, listless} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	setSDDL(t, ordinary, `D:P(A;OICI;FA;;;`+owner+`)(A;OICI;0x1301BF;;;BU)`)
	setSDDL(t, listless, "D:P"+"NO_ACCESS_CONTROL")
	t.Cleanup(func() {
		for _, dir := range []string{ordinary, listless} {
			setSDDL(t, dir, `D:P(A;OICI;FA;;;`+owner+`)`)
		}
	})
	secret := filepath.Join(root, "id_rsa")
	if err := os.WriteFile(secret, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Protect(secret); err != nil {
		t.Fatal(err)
	}

	if err := Isolate(root, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{ordinary, listless, secret} {
		if held, err := heldBy(path, unusedAccount, AccessModify); err != nil || held {
			t.Errorf("granting the tree above reached into %s (held=%v, err=%v)",
				filepath.Base(path), held, err)
		}
	}
	// And the reason the sweep went there at all still holds.
	if UsersWritable(ordinary) {
		t.Error("a protected descendant is still writable by BUILTIN\\Users")
	}
	if EveryoneWritable(listless) {
		t.Error("a protected descendant with no list is still writable by Everyone")
	}
}
