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
