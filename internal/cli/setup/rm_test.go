// Tests for taking a sandbox away: every permission back, what will not go
// named rather than skipped, and finishing when the record that lists it all
// is missing or will not parse.

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	acct "github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
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
	writable, err := access.Check(access.Sandbox{Group: removed}, filepath.Join(inner, "f.txt"), access.Create)
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

	after, err := access.Check(access.Sandbox{Group: removed}, filepath.Join(inner, "f.txt"), access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if after.Allowed {
		t.Error("a deleted sandbox still reaches inside what a nested grant pinned")
	}
	// The sandbox the inner directory belongs to is untouched by any of it.
	kept, err := access.Check(access.Sandbox{Group: other}, filepath.Join(inner, "f.txt"), access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !kept.Allowed {
		t.Errorf("removing one sandbox cost another its own grant: %s", kept.Reason)
	}
}

// TestRemovalClearsTheProfileEvenWithNoAccountLeft is the regression guard
// for a profile nothing could ever get rid of.
//
// removeAccount used to leave at once when the account was gone -- no
// account, nothing to do. But an attempt that deleted the account and then
// failed on the directory left exactly that state, and every later attempt
// walked straight past it. A thin profile is a couple of megabytes; one
// somebody has added to is gigabytes, and it was stranded for good.
func TestRemovalClearsTheProfileEvenWithNoAccountLeft(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const name = "wub-stranded-00000000"

	profile := sandbox.ProfileDir(name)
	if err := os.MkdirAll(filepath.Join(profile, "AppData", "Local"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "NTUSER.DAT"), []byte("a hive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if accountExists(acct.NameFor(name)) {
		t.Skip("an account by this name really exists here, which this test is not about")
	}

	if err := removeAccount(name, true); err != nil {
		t.Fatalf("removing a sandbox whose account is already gone: %v", err)
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Errorf("the profile directory survived, with no account left to ever come back for it: %v", err)
	}
}
