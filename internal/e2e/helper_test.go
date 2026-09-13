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

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
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
}

// newBox prepares a project directory with the test SID granted on it.
func newBox(t *testing.T) *box {
	t.Helper()
	root := t.TempDir()
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
	s := &state.State{Group: "wub-test", SID: testSID(t), Dir: granted, Temp: temp}
	if err := s.Add(granted, grant.RW); err != nil {
		t.Fatalf("grant project directory: %v", err)
	}
	if err := s.Add(temp, grant.RW); err != nil {
		t.Fatalf("grant temp directory: %v", err)
	}
	return &box{state: s, root: root, granted: granted, denied: denied}
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
