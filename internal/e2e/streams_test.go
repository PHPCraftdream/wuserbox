// What comes back out of a sandbox: that a shell starts inside a real
// account at all, that the program's exit code survives the two processes
// between it and the caller, and that its stdout and stderr do. The fixture
// is in account_test.go.

package e2e

import (
	"os"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

// TestAShellStartsInsideARealAccount is the whole reason a sandbox stopped
// being a restricted token. Under one, bash died before main with "couldn't
// create signal pipe, Win32 error 5", and no change to the restricting list
// could fix it.
func TestAShellStartsInsideARealAccount(t *testing.T) {
	requireAdministrator(t)
	const bash = `C:\Program Files\Git\bin\bash.exe`
	if _, err := os.Stat(bash); err != nil {
		t.Skip("Git for Windows is not installed here, so there is no MSYS program to start")
	}
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	box := newRealBox(t, firstSandbox, root)
	box.hand(t, root, grant.RW)

	if !box.tries(t, `"`+bash+`" --version`, root) {
		t.Error("bash did not start inside a sandbox, which is the failure the account exists to remove")
	}
}

// TestTheExitCodeComesBackFromInsideTheSandbox is the property everything
// built on wuserbox depends on and nothing else here measures: `wuserbox go
// test` has to fail when the tests fail.
//
// It is measured on the real chain rather than on the shape of it, because
// the chain is where it could go wrong: the code is read and handed on twice,
// once by the stub inside the account and once by the run out here, across a
// logon boundary in between. 7, because 1 is what half the things that go
// wrong on the way report by themselves.
func TestTheExitCodeComesBackFromInsideTheSandbox(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	stub := stubBinary(t, root)
	box := newRealBox(t, firstSandbox, root)
	box.hand(t, root, grant.RW)

	if code := box.ends(t, box.throughTheStub(t, stub, `cmd.exe /c exit 7`), root); code != 7 {
		t.Errorf("the run ended with %d, and the program inside ended with 7", code)
	}
}

// TestTheStreamsComeBackFromInsideTheSandbox checks all three standard
// handles through the real account -> stub -> restricted program chain. A
// command that reads stdin and writes both output streams makes a successful
// exit alone insufficient evidence that the handles were wired correctly.
func TestTheStreamsComeBackFromInsideTheSandbox(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	stub := stubBinary(t, root)
	box := newRealBox(t, firstSandbox, root)
	box.hand(t, root, grant.RW)

	stdout, stderr := box.streams(t, stub, root)
	if !strings.Contains(stdout, "from-stdin") || !strings.Contains(stdout, "stdout") {
		t.Errorf("sandbox stdout was %q, want stdin and stdout markers", stdout)
	}
	if !strings.Contains(stderr, "stderr") {
		t.Errorf("sandbox stderr was %q, want stderr marker", stderr)
	}
}
