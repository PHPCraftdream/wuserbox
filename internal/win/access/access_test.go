package access

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

const testGroup = "S-1-5-21-1111111111-2222222222-3333333333-909090"

func TestParseAcceptsTheFourOperations(t *testing.T) {
	for _, word := range []string{"read", "write", "create", "delete"} {
		if _, err := Parse(word); err != nil {
			t.Errorf("%s: %v", word, err)
		}
	}
	if _, err := Parse("rename"); err == nil {
		t.Error("an unknown operation should be rejected")
	}
}

// prepared returns a directory the test group may write to, and one it may not.
func prepared(t *testing.T) (granted, denied string) {
	t.Helper()
	root := t.TempDir()
	granted, denied = filepath.Join(root, "granted"), filepath.Join(root, "denied")
	for _, dir := range []string{granted, denied} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Without administrator rights the integrity label does not go on, and
	// these tests are about the permissions rather than the label.
	if err := grant.Apply(testGroup, granted, grant.RW); !grant.Applied(err) {
		t.Fatal(err)
	}
	return granted, denied
}

func TestCheckFollowsThePermissions(t *testing.T) {
	granted, denied := prepared(t)
	for _, file := range []string{filepath.Join(granted, "f.txt"), filepath.Join(denied, "f.txt")} {
		if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		path      string
		operation Operation
		want      bool
	}{
		{filepath.Join(granted, "f.txt"), Write, true},
		{filepath.Join(granted, "f.txt"), Delete, true},
		{filepath.Join(granted, "new.txt"), Create, true},
		{filepath.Join(denied, "f.txt"), Write, false},
		{filepath.Join(denied, "new.txt"), Create, false},
		{filepath.Join(denied, "f.txt"), Read, true}, // reading is not restricted
	}
	for _, c := range cases {
		result, err := Check(testGroup, c.path, c.operation, false)
		if err != nil {
			t.Errorf("%s %s: %v", c.operation, c.path, err)
			continue
		}
		if result.Allowed != c.want {
			t.Errorf("%s %s: allowed=%v, want %v (%s)",
				c.operation, c.path, result.Allowed, c.want, result.Reason)
		}
		if result.Reason == "" {
			t.Errorf("%s %s: no reason given", c.operation, c.path)
		}
	}
}

// TestCheckRefusesDeletionWhenNeitherDoorIsOpen is kept apart from the table
// above because it depends on the machine: a temporary directory that hands
// out the right to remove things from it opens the second door before the test
// says anything, and then there is nothing to test here.
func TestCheckRefusesDeletionWhenNeitherDoorIsOpen(t *testing.T) {
	_, denied := prepared(t)
	file := filepath.Join(denied, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if through, err := deleteThroughParent(testGroup, file, false); err != nil {
		t.Fatal(err)
	} else if through {
		t.Skip("the temporary directory on this machine lets the sandbox remove what is inside it")
	}
	answer, err := Check(testGroup, file, Delete, false)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("deletion was allowed with both doors shut: %s", answer.Reason)
	}
}

func TestCheckAnswersAboutTheParentWhenCreating(t *testing.T) {
	granted, _ := prepared(t)
	missing := filepath.Join(granted, "not-there-yet.txt")
	result, err := Check(testGroup, missing, Create, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Checked != granted {
		t.Errorf("the question was asked about %s, want %s", result.Checked, granted)
	}
	if !result.Allowed {
		t.Errorf("creating in a writable directory was refused: %s", result.Reason)
	}
}

func TestCheckReportsAMissingPath(t *testing.T) {
	granted, _ := prepared(t)
	if _, err := Check(testGroup, filepath.Join(granted, "absent"), Write, false); err == nil {
		t.Error("expected an error for a path that does not exist")
	}
}

func TestCheckChangesNothing(t *testing.T) {
	granted, denied := prepared(t)
	before, err := os.ReadDir(granted)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range Operations {
		_, _ = Check(testGroup, filepath.Join(granted, "probe.txt"), operation, false)
		_, _ = Check(testGroup, denied, operation, false)
	}
	after, err := os.ReadDir(granted)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("asking created something: %d entries, was %d", len(after), len(before))
	}
}

func TestCheckAgreesWithARealWrite(t *testing.T) {
	// The answer is only worth anything if it matches what happens.
	granted, denied := prepared(t)
	if err := acl.Protect(filepath.Join(denied)); err != nil {
		t.Fatal(err)
	}
	allowed, err := Check(testGroup, granted, Create, false)
	if err != nil {
		t.Fatal(err)
	}
	refused, err := Check(testGroup, denied, Create, false)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Allowed || refused.Allowed {
		t.Errorf("granted=%v denied=%v", allowed.Allowed, refused.Allowed)
	}
}

// TestCheckLeavesTheThreadAsItFoundIt is the regression guard for the subtlest
// of the failures here: impersonation belongs to an operating-system thread,
// so a check that ends on a different thread than it started on leaves the
// first one wearing the sandbox token. Whatever the runtime schedules there
// next would then fail for no visible reason.
//
// The test runs many checks from many goroutines, which is what makes the
// runtime move them between threads, and then confirms that ordinary writes
// still work from every one of them.
func TestCheckLeavesTheThreadAsItFoundIt(t *testing.T) {
	granted, denied := prepared(t)

	var wait sync.WaitGroup
	failures := make(chan string, 64)
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for round := 0; round < 8; round++ {
				if _, err := Check(testGroup, denied, Write, false); err != nil {
					failures <- fmt.Sprintf("worker %d: %v", worker, err)
					return
				}
				// The caller's own rights must be intact afterwards: this
				// write goes to a directory the sandbox may not touch.
				name := filepath.Join(denied, fmt.Sprintf("worker-%d-%d.txt", worker, round))
				if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
					failures <- fmt.Sprintf("worker %d lost its own rights: %v", worker, err)
					return
				}
				if _, err := os.ReadDir(granted); err != nil {
					failures <- fmt.Sprintf("worker %d cannot read: %v", worker, err)
					return
				}
			}
		}(worker)
	}
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

func TestCheckReportsAFailureToAskRatherThanGuessing(t *testing.T) {
	// A malformed group cannot produce a token, so the answer must be an
	// error and not a cheerful "allowed".
	result, err := Check("not-a-sid", t.TempDir(), Write, false)
	if err == nil {
		t.Fatal("expected an error")
	}
	if result.Allowed {
		t.Error("a failed check reported the operation as allowed")
	}
}

// TestCheckHonoursTheReadOnlyMark is the regression guard for an answer that
// consulted the permission list alone. A file marked read-only is refused by
// the file system whatever the permissions say, so "allowed" was a promise the
// write could not keep.
func TestCheckHonoursTheReadOnlyMark(t *testing.T) {
	granted, _ := prepared(t)
	file := filepath.Join(granted, "locked.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	before, err := Check(testGroup, file, Write, false)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Allowed {
		t.Fatal("the file was not writable to begin with")
	}

	if err := os.Chmod(file, 0o444); err != nil {
		t.Fatal(err)
	}
	after, err := Check(testGroup, file, Write, false)
	if err != nil {
		t.Fatal(err)
	}
	if after.Allowed {
		t.Error("a read-only file was reported as writable")
	}
	if !strings.Contains(after.Reason, "read-only") {
		t.Errorf("the reason does not mention the mark: %q", after.Reason)
	}
	// Reading is unaffected by the mark.
	readable, err := Check(testGroup, file, Read, false)
	if err != nil {
		t.Fatal(err)
	}
	if !readable.Allowed {
		t.Error("a read-only file was reported as unreadable")
	}
	_ = os.Chmod(file, 0o644)
}

func TestCheckIgnoresTheMarkOnDirectories(t *testing.T) {
	// Windows sets the same bit on directories for unrelated reasons, so it
	// must not be read as a refusal there.
	granted, _ := prepared(t)
	result, err := Check(testGroup, granted, Create, false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Errorf("a writable directory was refused: %s", result.Reason)
	}
}

// TestCheckSeesDeletionThroughTheParent is the regression guard for an answer
// that knew only half the rule. Windows lets something go when the thing
// itself may be deleted, or when the directory holding it may have things
// removed from it. An answer that asked only about the file promised a refusal
// that did not happen.
func TestCheckSeesDeletionThroughTheParent(t *testing.T) {
	granted, _ := prepared(t)
	file := filepath.Join(granted, "child.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The file itself says no to everyone but its owner.
	if err := acl.Protect(file); err != nil {
		t.Fatal(err)
	}
	// The ordinary permission on a directory does not carry the right to
	// remove things from it, so with the file itself closed both doors are
	// shut. Unless the machine's temporary directory says otherwise, in which
	// case only the second half of this test means anything.
	if through, err := deleteThroughParent(testGroup, file, false); err != nil {
		t.Fatal(err)
	} else if !through {
		onTheFile, err := Check(testGroup, file, Delete, false)
		if err != nil {
			t.Fatal(err)
		}
		if onTheFile.Allowed {
			t.Errorf("deletion was allowed without either door being open: %s", onTheFile.Reason)
		}
	}

	// Open the second door and the answer has to change. It takes both sides:
	// a sandbox is bounded by its own permission and by the caller's, so the
	// right to remove things from the directory has to be there for each.
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{owner, testGroup} {
		if err := acl.Set(granted, account, []acl.ACE{
			{Access: acl.AccessModify | DeleteChild, Inheritance: acl.InheritObjects | acl.InheritContainers},
		}); err != nil {
			t.Fatal(err)
		}
	}
	throughParent, err := Check(testGroup, file, Delete, false)
	if err != nil {
		t.Fatal(err)
	}
	if !throughParent.Allowed {
		t.Errorf("deletion through the directory was not noticed: %s", throughParent.Reason)
	}
	if !strings.Contains(throughParent.Reason, "directory holding it") {
		t.Errorf("the reason does not say which door is open: %q", throughParent.Reason)
	}
}

// TestCheckHonoursTheReadOnlyMarkOnDeletionThroughTheParent is the regression
// guard for an answer that stopped as soon as the second door was open. A file
// marked read-only is refused by the file system whatever a permission says,
// including a deletion the holding directory would otherwise allow, and the
// check promised one that a real attempt did not get.
func TestCheckHonoursTheReadOnlyMarkOnDeletionThroughTheParent(t *testing.T) {
	granted, _ := prepared(t)
	file := filepath.Join(granted, "locked.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Open the door on the directory for both sides, so deletion would be
	// allowed if the file were an ordinary one.
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{owner, testGroup} {
		if err := acl.Set(granted, account, []acl.ACE{
			{Access: acl.AccessModify | DeleteChild, Inheritance: acl.InheritObjects | acl.InheritContainers},
		}); err != nil {
			t.Fatal(err)
		}
	}
	// And close the file itself, so the only way in is through the directory.
	if err := acl.Protect(file); err != nil {
		t.Fatal(err)
	}
	through, err := deleteThroughParent(testGroup, file, false)
	if err != nil {
		t.Fatal(err)
	}
	if !through {
		t.Skip("this machine does not pass the right to remove things down, " +
			"so the door this test is about cannot be opened here")
	}

	if err := os.Chmod(file, 0o444); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(file, 0o644) }()
	answer, err := Check(testGroup, file, Delete, false)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("a read-only file was reported as deletable: %s", answer.Reason)
	}
	if !strings.Contains(answer.Reason, "read-only") {
		t.Errorf("the reason does not mention the mark: %q", answer.Reason)
	}
}
