// Taking a sandbox away when the record that lists what it holds is missing,
// half-written or will not parse -- and what a preview of that removal says.
//
// Removal is the one command that has to go on anyway. Every other command
// stops on a record it cannot read, and should: acting on a sandbox whose
// permissions are unknown is how permissions get left behind. Refusing here
// made the sandbox impossible to remove at all, which is the failure these
// hold against. The ordinary path is in rm_test.go.

package setup

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

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
	if err := grant.Apply(account.String(), project, grant.RW, nil); err != nil {
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
		if err := grant.Apply(account.String(), path, grant.RW, nil); err != nil {
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

// TestRemovingASandboxDiscardsTheCopyWhenTheRecordIsAlreadyGone is the
// regression guard for the two bookkeeping files going missing separately.
//
// The copy was only deleted where a record had been read, so deleting the
// record by hand left the copy behind for good. That is not merely untidy: a
// later sandbox of the same name has no copy of its own until its second save,
// so until then the stale one stands behind its record, naming directories
// that answered to a group which no longer exists.
func TestRemovingASandboxDiscardsTheCopyWhenTheRecordIsAlreadyGone(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const name = "wub-leftover-copy"
	recordWithACopy(t, name)

	// The record deleted by hand, the copy beside it untouched.
	if err := os.Remove(state.Path(name)); err != nil {
		t.Fatal(err)
	}
	if err := removeSandbox(name, true); err != nil {
		t.Fatalf("removing a sandbox whose record is already gone failed: %v", err)
	}

	if _, err := os.Stat(state.PreviousPath(name)); !os.IsNotExist(err) {
		t.Errorf("the copy at %s outlived the sandbox it describes: %v",
			state.PreviousPath(name), err)
	}
}

// TestThePreviewNamesEveryFileRemovalWouldDelete keeps --dry-run honest about
// the copy. A preview that names one of the two files says less than it knows
// about what the command it is previewing would do.
func TestThePreviewNamesEveryFileRemovalWouldDelete(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const name = "wub-preview-copy"
	recordWithACopy(t, name)

	shown := captureStdout(t, func() error { return previewRemoval(name, false) })
	for _, path := range []string{state.Path(name), state.PreviousPath(name)} {
		if !strings.Contains(shown, path) {
			t.Errorf("the preview does not mention %s:\n%s", path, shown)
		}
	}
}

// TestThePreviewOfADamagedRecordStillNamesItsGrants is the other half of that.
// The preview read the record more strictly than removal does, so a record
// that had stopped parsing made it list nothing at all, while the removal it
// was previewing would have gone ahead and taken every grant back from the
// copy behind it.
func TestThePreviewOfADamagedRecordStillNamesItsGrants(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const name = "wub-preview-damaged"
	s := recordWithACopy(t, name)
	if err := os.WriteFile(state.Path(name), []byte("{ not a record"), 0o600); err != nil {
		t.Fatal(err)
	}

	shown := captureStdout(t, func() error { return previewRemoval(name, false) })
	if !strings.Contains(shown, s.Grants[0].Path) {
		t.Errorf("the preview says nothing about %s, which removal would take back:\n%s",
			s.Grants[0].Path, shown)
	}
}

// recordWithACopy writes a record twice, which is what leaves a copy behind
// it, and returns what was written.
func recordWithACopy(t *testing.T, name string) *state.State {
	t.Helper()
	held := t.TempDir()
	s := &state.State{
		Group: name, SID: "S-1-5-21-1111111111-2222222222-3333333333-654321",
		Dir: held, Temp: t.TempDir(),
		Grants: []grant.Spec{{Path: held, Kind: grant.RW, Explicit: true}},
	}
	for i := 0; i < 2; i++ {
		if err := s.Save(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(state.PreviousPath(name)); err != nil {
		t.Fatalf("no copy was kept, so this proves nothing: %v", err)
	}
	return s
}

// captureStdout runs something that prints, and hands back what it printed.
func captureStdout(t *testing.T, run func() error) string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = write
	printed := make(chan string, 1)
	go func() {
		var collected strings.Builder
		_, _ = io.Copy(&collected, read)
		printed <- collected.String()
	}()
	runErr := run()
	os.Stdout = saved
	_ = write.Close()
	shown := <-printed
	_ = read.Close()
	if runErr != nil {
		t.Fatal(runErr)
	}
	return shown
}
