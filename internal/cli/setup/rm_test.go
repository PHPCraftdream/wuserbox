// Tests for taking a sandbox away: every permission back, what will not go
// named rather than skipped, and finishing when the record that lists it all
// is missing or will not parse.

package setup

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// TestRemoveSandboxKeepsTheRecordWhenSomethingIsLeftBehind is the regression
// guard for a removal that printed its failures and reported success. A temp
// directory held open by another program stayed on disk while the record and
// the group that named it were deleted, so nothing was left to finish the job
// with and the command still exited 0.
func TestRemoveSandboxKeepsTheRecordWhenSomethingIsLeftBehind(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	temp := t.TempDir()
	s := &state.State{
		Group: "wub-rm-test",
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-202020",
		Dir:   t.TempDir(),
		Temp:  temp,
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	release := holdOpen(t, filepath.Join(temp, "busy.log"))
	defer release()

	err := removeSandbox(s.Group, false)
	if got := exit.Of(err); got != exit.Failed {
		t.Fatalf("exit code is %v, want %v (error: %v)", got, exit.Failed, err)
	}
	if _, statErr := os.Stat(state.Path(s.Group)); statErr != nil {
		t.Errorf("the record was deleted although the removal did not finish: %v", statErr)
	}

	// Once the obstacle is gone, running it again has to finish the job.
	release()
	if err := removeSandbox(s.Group, false); err != nil {
		t.Fatalf("the second attempt did not finish: %v", err)
	}
	if _, statErr := os.Stat(state.Path(s.Group)); !os.IsNotExist(statErr) {
		t.Errorf("the record survived a successful removal: %v", statErr)
	}
	if _, statErr := os.Stat(temp); !os.IsNotExist(statErr) {
		t.Error("the temp directory survived a successful removal")
	}
}

// TestRemoveSandboxSaysNothingAboutASandboxThatWasNeverThere keeps removal
// harmless where there is nothing to remove.
func TestRemoveSandboxSaysNothingAboutASandboxThatWasNeverThere(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if err := removeSandbox("wub-never-created", false); err != nil {
		t.Errorf("removing a sandbox that does not exist failed: %v", err)
	}
}

// holdOpen keeps a file open without letting anyone delete it, the way an
// editor or a running program does, and returns the release. Releasing twice
// is harmless.
func holdOpen(t *testing.T, path string) func() {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ,
		nil, syscall.CREATE_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		_ = syscall.CloseHandle(handle)
	}
}

// TestRemoveSandboxFinishesWhenAGrantedDirectoryIsGone is the regression guard
// for a removal that could never complete. A directory in the record that had
// since been deleted was counted as a permission that would not go, so every
// attempt failed on the same missing path and the sandbox stayed on the
// machine for good.
func TestRemoveSandboxFinishesWhenAGrantedDirectoryIsGone(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	gone := filepath.Join(t.TempDir(), "was-here")
	if err := os.Mkdir(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &state.State{
		Group: "wub-rm-missing",
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-212121",
		Dir:   t.TempDir(),
		Temp:  t.TempDir(),
	}
	if err := s.Add(gone, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}

	if err := removeSandbox(s.Group, false); err != nil {
		t.Fatalf("removal did not finish over a directory that no longer exists: %v", err)
	}
	if _, err := os.Stat(state.Path(s.Group)); !os.IsNotExist(err) {
		t.Errorf("the record survived a successful removal: %v", err)
	}
}

// TestRmRefusesADirectoryGivenAsAnArgument is the regression guard for a
// command given a directory as an argument: it ignored the path and removed
// the sandbox of the current directory instead.
func TestRmRefusesADirectoryGivenAsAnArgument(t *testing.T) {
	err := Rm([]string{t.TempDir(), "--dry-run"})
	if got := exit.Of(err); got != exit.Usage {
		t.Fatalf("exit code is %v, want %v (error: %v)", got, exit.Usage, err)
	}
	if !strings.Contains(err.Error(), "--dir") {
		t.Errorf("the message does not say how to name a project: %v", err)
	}
}

// TestClearGrantsReachesWhatANestedGrantPinned is the regression guard for the
// half of --rm that was never there.
//
// Deleting a sandbox revoked each path it held and stopped. Handing a
// directory over pins its permission list, copying what it was handed from
// above into its own entries, so a directory inside a granted one that another
// sandbox was given carries a copy of this sandbox's entry — and that copy no
// longer hears from the directory above it. Revoking the outer path left it
// standing, and --rm went on to delete the group and report success over
// permissions that were still in force with nothing left pointing at them.
func TestClearGrantsReachesWhatANestedGrantPinned(t *testing.T) {
	const (
		removed = "S-1-5-21-1111111111-2222222222-3333333333-515151"
		other   = "S-1-5-21-1111111111-2222222222-3333333333-525252"
	)
	outer := t.TempDir()
	inner := filepath.Join(outer, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := grant.Apply(removed, outer, grant.RW); err != nil {
		t.Fatal(err)
	}
	// Granting the inner one to somebody else is what pins it, with the entry
	// of the sandbox about to be deleted among the copies.
	if err := grant.Apply(other, inner, grant.RW); err != nil {
		t.Fatal(err)
	}
	writable, err := access.Check(removed, filepath.Join(inner, "f.txt"), access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !writable.Allowed {
		t.Fatal("the sandbox could not write inside the pinned directory, so this proves nothing")
	}

	s := &state.State{
		Group:  "wub-rm-test",
		SID:    removed,
		Dir:    outer,
		Temp:   t.TempDir(),
		Grants: []grant.Spec{{Path: outer, Kind: grant.RW}},
	}
	if left := clearGrants(s, true); len(left) > 0 {
		t.Fatalf("clearing the grants did not finish: %v", left)
	}

	after, err := access.Check(removed, filepath.Join(inner, "f.txt"), access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if after.Allowed {
		t.Error("a deleted sandbox still reaches inside what a nested grant pinned")
	}
	// The sandbox the inner directory belongs to is untouched by any of it.
	kept, err := access.Check(other, filepath.Join(inner, "f.txt"), access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !kept.Allowed {
		t.Errorf("removing one sandbox cost another its own grant: %s", kept.Reason)
	}
}

// TestRemovingASandboxWithNoRecordStillClearsItsProjectDirectory is the
// regression guard for a removal that reported success and left permissions
// behind that nothing could ever find again.
//
// The record is the list of what a sandbox holds. With it gone — deleted by
// hand, or lost with the profile it lived in — removal went straight to
// deleting the group, and every entry naming that group stayed on disk while
// the identifier in them stopped resolving. The group's own comment still
// remembers the directory it belongs to, so at least that much can be cleared
// before the name goes.
func TestRemovingASandboxWithNoRecordStillClearsItsProjectDirectory(t *testing.T) {
	if !token.IsAdmin() {
		t.Skip("creating and deleting a local group needs administrator rights")
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	project := t.TempDir()
	name := fmt.Sprintf("%srmtest-%d", group.Prefix, 100000+rand.Intn(800000))
	if _, err := sid.Lookup(name); err == nil {
		t.Skipf("%s already exists on this machine", name)
	}
	if err := group.Add(name, project); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Delete(name) })
	account, err := sid.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := grant.Apply(account.String(), project, grant.RW); err != nil {
		t.Fatal(err)
	}
	if !acl.Reads(project, account.String()) {
		t.Fatal("the grant did not take, so this proves nothing")
	}

	// No record at all: exactly what removal used to walk straight past.
	if _, err := os.Stat(state.Path(name)); !os.IsNotExist(err) {
		t.Fatalf("this sandbox was not supposed to have a record: %v", err)
	}
	if err := remove(name, false); err != nil {
		t.Fatal(err)
	}

	if acl.Reads(project, account.String()) {
		t.Error("the group was deleted and its entries were left on the project directory")
	}
	if _, exists, err := group.Comment(name); err != nil || exists {
		t.Errorf("the group survived removal (exists=%v, err=%v)", exists, err)
	}
}

// TestRemovalGoesOnWithACopyWhenTheRecordWillNotParse is the part of the guard
// below that needs no local group, so it runs everywhere.
//
// Removal used to pass the read failure straight on, which stopped the one
// command whose job is to clean up: the group stayed and so did every entry
// naming it. Here the record is damaged and the copy behind it still names the
// directory the sandbox holds, so removal has something to work from.
func TestRemovalGoesOnWithACopyWhenTheRecordWillNotParse(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	held := t.TempDir()
	name := "wub-recordfor-test"
	s := &state.State{
		Group: name, SID: "S-1-5-21-1111111111-2222222222-3333333333-654321",
		Dir: held, Temp: t.TempDir(),
		Grants: []grant.Spec{{Path: held, Kind: grant.RW, Explicit: true}},
	}
	// One save writes the record; the second is what leaves a copy behind it.
	for i := 0; i < 2; i++ {
		if err := s.Save(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(state.Path(name), []byte("{ not a record"), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, damaged, err := recordFor(name, true)
	if err != nil {
		t.Fatalf("removal gave up on a record it could not read: %v", err)
	}
	if !damaged {
		t.Error("a record that will not parse was reported as a sound one")
	}
	if loaded == nil {
		t.Fatal("the copy behind the record was not used, so the grants in it are unreachable")
	}
	if len(loaded.Grants) != 1 || !strings.EqualFold(loaded.Grants[0].Path, held) {
		t.Errorf("removal would go on with %v, not %s", loaded.Grants, held)
	}
}

// TestRemovingASandboxWithADamagedRecordClearsWhatTheCopyRemembers is the
// regression guard for a record that is there and will not parse.
//
// Reading it failed, and removal passed that failure straight on, so the one
// command whose job is to clean up could not run at all: the group stayed, and
// so did every entry naming it. The directory the group's comment remembers
// could have been cleared even then, and anything handed over elsewhere could
// not have been — nothing else on the machine says where those are.
//
// So the record now keeps a copy of itself from before the last save, and that
// copy is what names the directory outside the project here. Removal says what
// happened, goes on with the copy, and finishes.
func TestRemovingASandboxWithADamagedRecordClearsWhatTheCopyRemembers(t *testing.T) {
	if !token.IsAdmin() {
		t.Skip("creating and deleting a local group needs administrator rights")
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	project, elsewhere := t.TempDir(), t.TempDir()
	name := fmt.Sprintf("%srmtest-%d", group.Prefix, 100000+rand.Intn(800000))
	if _, err := sid.Lookup(name); err == nil {
		t.Skipf("%s already exists on this machine", name)
	}
	if err := group.Add(name, project); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Delete(name) })
	account, err := sid.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{project, elsewhere} {
		if err := grant.Apply(account.String(), path, grant.RW); err != nil {
			t.Fatal(err)
		}
		if !acl.Reads(path, account.String()) {
			t.Fatalf("the grant on %s did not take, so this proves nothing", path)
		}
	}
	s := &state.State{
		Group: name, SID: account.String(), Dir: project, Temp: t.TempDir(),
		Grants: []grant.Spec{
			{Path: project, Kind: grant.RW, Explicit: true},
			{Path: elsewhere, Kind: grant.RW, Explicit: true},
		},
	}
	// Twice: the first save writes the record, the second is what leaves the
	// copy behind it. That is the state a sandbox is in after any ordinary run.
	for i := 0; i < 2; i++ {
		if err := s.Save(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(state.Path(name), []byte("{ this is not a record"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := remove(name, false); err != nil {
		t.Fatalf("removal gave up on a record it could not read: %v", err)
	}

	if acl.Reads(elsewhere, account.String()) {
		t.Error("the directory outside the project kept its entry, and the group naming it is gone")
	}
	if acl.Reads(project, account.String()) {
		t.Error("the project directory kept its entry")
	}
	if _, exists, err := group.Comment(name); err != nil || exists {
		t.Errorf("the group survived removal (exists=%v, err=%v)", exists, err)
	}
	for _, path := range []string{state.Path(name), state.PreviousPath(name)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s outlived the sandbox it describes: %v", path, err)
		}
	}
}
