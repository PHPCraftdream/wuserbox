package acl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

const unusedAccount = "S-1-5-21-1111111111-2222222222-3333333333-543210"

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

// TestIsolateReplacesEveryoneAndUsersWithReadOnly is the regression guard for
// peer isolation: a directory that already carries Everyone and Users write
// access -- the shape a directory takes when it merely inherited it from
// somewhere, the reviewer's mandatory case -- has to lose that access on the
// very same update that grants the account this call is for, or every other
// sandbox holding Everyone or Users (every sandbox does) could still reach it.
func TestIsolateReplacesEveryoneAndUsersWithReadOnly(t *testing.T) {
	dir := t.TempDir()
	inherited := []ACE{{Access: AccessModify, Inheritance: InheritObjects | InheritContainers}}
	if err := Set(dir, sid.Everyone, inherited); err != nil {
		t.Fatal(err)
	}
	if err := Set(dir, sid.Users, inherited); err != nil {
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
		t.Error("Isolate denied Everyone instead of replacing its access")
	}
	if !holds(t, dir, "Everyone", "(RX)") {
		t.Error("Everyone lost its read access instead of being narrowed to it")
	}
	// "BUILTIN\Users", not the bare word: "NT AUTHORITY\Authenticated Users"
	// also contains "Users" and would false-positive a substring match.
	if holds(t, dir, `BUILTIN\Users`, "(M)") {
		t.Error("Users still holds Modify after Isolate")
	}
	if holds(t, dir, `BUILTIN\Users`, "(DENY)") {
		t.Error("Isolate denied Users instead of replacing its access")
	}
	if !holds(t, dir, `BUILTIN\Users`, "(RX)") {
		t.Error("Users lost its read access instead of being narrowed to it")
	}
	if !holds(t, dir, unusedAccount, "(M)") {
		t.Error("the account this call was for did not get its own grant")
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
	publish = func(path string, list []explicitAccess) error {
		updates++
		return original(path, list)
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
