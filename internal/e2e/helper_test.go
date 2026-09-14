// Package e2e checks the security property wuserbox exists for: a sandboxed
// process reads what the caller can read, and writes only where an entry for
// the sandbox SID allows it. The tests use a synthetic SID instead of a real
// local group, so they need no administrator rights.
package e2e

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// testSID returns a SID that belongs to no account on this machine. Access
// control entries accept it, and it appears in no other DACL, so a grant is
// the only reason a sandboxed write can succeed.
func testSID(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("S-1-5-21-1111111111-2222222222-3333333333-%d", 100000+rand.Intn(800000))
}

// box is one prepared sandbox plus the directories a test writes into.
type box struct {
	state   *state.State
	root    string // holds granted and denied, with no entry of its own
	granted string // the project directory
	denied  string // a sibling the sandbox was never given
	// control is a file no grant names, used to ask what this machine hands
	// out on its own. It is never the subject of a test.
	control string
}

// newBox prepares a project directory with the test SID granted on it.
func newBox(t *testing.T) *box {
	t.Helper()
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	granted := filepath.Join(root, "project")
	denied := filepath.Join(root, "elsewhere")
	for _, dir := range []string{granted, denied} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	temp := filepath.Join(root, "temp")
	if err := os.Mkdir(temp, 0o755); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(root, "control.txt")
	if err := os.WriteFile(control, []byte("control"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &state.State{Group: "wub-test", SID: testSID(t), Dir: granted, Temp: temp}
	if err := s.Add(granted, grant.RW); err != nil {
		t.Fatalf("grant project directory: %v", err)
	}
	if err := s.Add(temp, grant.RW); err != nil {
		t.Fatalf("grant temp directory: %v", err)
	}
	return &box{state: s, root: root, granted: granted, denied: denied, control: control}
}

// closeOff refuses the sandbox everything that changes the given paths.
//
// How much a temporary directory hands down is not the same on every machine:
// a build machine lets anyone in the Users group delete what is inside, where a
// desktop does not, and a restricted token does not take that right away
// because it restricts writing rather than deleting. A test about the rule for
// deciding whether a question can be asked at all must not rest on that
// difference, so the refusal is stated outright.
//
// This belongs to those tests only. The tests about the boundary itself must
// keep asking what wuserbox alone arranges, and would be worth nothing if the
// answer were nailed down here.
func closeOff(t *testing.T, b *box, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if err := acl.Deny(path, b.state.SID, acl.AccessChange); err != nil {
			t.Fatalf("closing off %s: %v", path, err)
		}
	}
}

// machineIsOpen reports whether this machine hands out the right to delete
// things in the directory these tests run in, whatever wuserbox did. It asks
// about the control file, which no permission names, so an answer of yes can
// have come from nowhere else.
func machineIsOpen(t *testing.T, b *box) (bool, string) {
	t.Helper()
	answer, err := access.Check(b.state.SID, b.control, access.Delete)
	if err != nil {
		t.Fatalf("asking about %s: %v", b.control, err)
	}
	return answer.Allowed, answer.Reason
}

// skipIfTheMachineIsOpen leaves a test unrun where the machine itself makes
// its question unanswerable. It is for checks that destroy their own subject,
// such as a sweep over a whole tree, and that therefore cannot ask afterwards.
func skipIfTheMachineIsOpen(t *testing.T, b *box) {
	t.Helper()
	if open, reason := machineIsOpen(t, b); open {
		t.Skipf("this machine lets the sandbox delete %s, which no permission names, "+
			"so a boundary cannot be tested here: %s", b.control, reason)
	}
}

// deleteOutcome is what came of telling the sandbox to delete something.
type deleteOutcome int

const (
	// refused: the path survived, which is what a boundary test wants.
	refused deleteOutcome = iota
	// deleted: the sandbox removed it, and a boundary did not hold.
	deleted
	// unanswerable: this machine hands out rights of its own, so the
	// question cannot be asked here at all.
	unanswerable
)

// attemptDelete tells the sandbox to delete a path and reports what happened.
//
// Whether the machine is open is decided from the control file, which no grant
// names and which no test is about. Deciding it from the path under test would
// be worse than useless: a token or an access control entry that stopped
// working would let the sandbox delete exactly what it must not, and that
// answer would be read as a reason to look away.
func attemptDelete(t *testing.T, b *box, path string) (deleteOutcome, string) {
	t.Helper()
	if open, reason := machineIsOpen(t, b); open {
		return unanswerable, reason
	}
	runSandboxed(t, b.state, []string{"cmd.exe", "/c", "del /q " + path})
	if exists(path) {
		return refused, ""
	}
	return deleted, ""
}

// writeFileCommand is a shell command that creates a file, failing if it cannot.
func writeFileCommand(path string) []string {
	return []string{"cmd.exe", "/c", "echo sandbox-wrote-this>" + path}
}

// script writes a batch file into the project directory and returns the
// command to run it. Anything involving quotes or environment variables goes
// through a script, because the command interpreter parses its own quoting.
func script(t *testing.T, b *box, body string) []string {
	t.Helper()
	path := filepath.Join(b.granted, "check.cmd")
	if err := os.WriteFile(path, []byte("@echo off\r\n"+body+"\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return []string{path}
}

// mustNotDelete checks that the sandbox cannot remove a path, failing when it
// can and skipping only where the machine itself makes the question
// unanswerable.
func mustNotDelete(t *testing.T, b *box, path string) {
	t.Helper()
	switch outcome, reason := attemptDelete(t, b, path); outcome {
	case unanswerable:
		t.Skipf("this machine lets the sandbox delete %s, which no permission names, "+
			"so a boundary cannot be tested here: %s", b.control, reason)
	case deleted:
		t.Errorf("%s was deleted from inside the sandbox", path)
	}
}
