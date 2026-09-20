// What comes back out of a sandbox: that a shell starts inside a real
// account at all, that the program's exit code survives the two processes
// between it and the caller, and that its stdout and stderr do. The fixture
// is in account_test.go.

package e2e

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
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

// TestAProgramThatNeedsARealTerminalFindsOneUnderOwnConsole measures the
// thing --own-console exists for: that the account -> stub -> restricted
// token chain hands the program console handles GetConsoleMode answers.
// Without them a raw-mode terminal program refuses to start at all, which is
// what a pipe -- every run's standard input until now -- can never be. The
// program is powershell reporting [Console]::IsInputRedirected, the same
// check shape codex's own isatty makes before it will enter raw mode, and
// the same command line runs twice through the stub: once the way every run
// has always gone, stdin a redirected pipe, where the answer is True; once
// with WUSERBOX_OWN_CONSOLE set, where the stub allocates a console of its
// own and hands it over, and the answer is False.
//
// The cost is a real window. The positive run allocates a console, and a
// console comes with a window on the desktop for the length of the run --
// one window, one test, the price of measuring the thing for real instead of
// through a surrogate. That is also why this test inherits this file's
// administrator gate and skips without it.
func TestAProgramThatNeedsARealTerminalFindsOneUnderOwnConsole(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	stub := stubBinary(t, root)
	box := newRealBox(t, firstSandbox, root)
	box.hand(t, root, grant.RW)

	// run starts the probe once and holds its answer against want: what
	// PowerShell wrote into resultFile is [Console]::IsInputRedirected's
	// own verdict on the stdin the program actually received.
	run := func(resultFile, want string, env []string) {
		t.Helper()
		if err := os.Remove(resultFile); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		commandLine := fmt.Sprintf(`powershell.exe -NoProfile -Command "Set-Content -LiteralPath '%s' -Value ([Console]::IsInputRedirected)"`, resultFile)
		line := box.throughTheStub(t, stub, commandLine)
		code, err := proc.RunAsAccount(box.account, box.password, line, root, env)
		if err != nil {
			t.Fatalf("starting %q as %s: %v", line, box.account, err)
		}
		if code != 0 {
			t.Fatalf("the terminal probe ended with exit code %d", code)
		}
		raw, err := os.ReadFile(resultFile)
		if err != nil {
			t.Fatalf("the terminal probe wrote no result (exit code %d): %v", code, err)
		}
		if got := strings.TrimSpace(string(raw)); got != want {
			t.Errorf("[Console]::IsInputRedirected was reported %q, want %q", got, want)
		}
	}

	run(filepath.Join(root, "tty-bridged.txt"), "True", os.Environ())
	run(filepath.Join(root, "tty-own-console.txt"), "False", append(os.Environ(), proc.EnvOwnConsole+"=1"))
}

// TestAProgramThroughTheConsoleRelaySeesARealTerminalAndRelaysItsBytes
// measures the relay end to end on the real account -> stub -> restricted
// program chain: the program's terminal is a pseudo console inside the
// sandbox, so the console check that answers True against the ordinary
// bridged pipes answers False here; its rendered output crosses the
// stub's stdout and lands on the run's own captured stdout; and a line
// fed to the run's stdin crosses the stub's pump into the console the
// program reads. Unlike --own-console there is no window: the console has
// none, which is also why this test costs the desktop nothing.
//
// The legs read answers the programs wrote to files wherever one exists,
// so no assertion depends on relay timing except the two that read the
// captured stream itself.
func TestAProgramThroughTheConsoleRelaySeesARealTerminalAndRelaysItsBytes(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	stub := stubBinary(t, root)
	box := newRealBox(t, firstSandbox, root)
	box.hand(t, root, grant.RW)

	// terminal runs the IsInputRedirected probe once per env and holds
	// the answer against want: through the ordinary bridge the program's
	// stdin is a redirected pipe; through the relay it is a real console,
	// which is the whole reason the relay exists.
	terminal := func(resultFile, want string, env []string) {
		t.Helper()
		if err := os.Remove(resultFile); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		commandLine := fmt.Sprintf(`powershell.exe -NoProfile -Command "Set-Content -LiteralPath '%s' -Value ([Console]::IsInputRedirected)"`, resultFile)
		line := box.throughTheStub(t, stub, commandLine)
		code, err := proc.RunAsAccount(box.account, box.password, line, root, env)
		if err != nil {
			t.Fatalf("starting %q as %s: %v", line, box.account, err)
		}
		if code != 0 {
			t.Fatalf("the terminal probe ended with exit code %d", code)
		}
		raw, err := os.ReadFile(resultFile)
		if err != nil {
			t.Fatalf("the terminal probe wrote no result (exit code %d): %v", code, err)
		}
		if got := strings.TrimSpace(string(raw)); got != want {
			t.Errorf("[Console]::IsInputRedirected was reported %q, want %q", got, want)
		}
	}
	terminal(filepath.Join(root, "tty-bridged.txt"), "True", os.Environ())
	terminal(filepath.Join(root, "tty-relay.txt"), "False", append(os.Environ(), proc.EnvConsoleRelay+"=1"))

	// relayed runs one command with the run's own stdin and stdout
	// standing in for the operator's console -- redirected pipes, the
	// shape every harness has -- and answers with what the captured
	// stdout received. The parent's bridge machinery works unchanged
	// here: stdout is not a console, so the run hands the stub a plain
	// duplicate of the pipe, and the stub's pump writes the relay's
	// rendered bytes into it.
	relayed := func(commandLine, stdinText string) string {
		t.Helper()
		inRead, inWrite, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		outRead, outWrite, err := os.Pipe()
		if err != nil {
			inRead.Close()
			inWrite.Close()
			t.Fatal(err)
		}
		if stdinText != "" {
			if _, err := inWrite.WriteString(stdinText); err != nil {
				t.Fatal(err)
			}
		}
		if err := inWrite.Close(); err != nil {
			t.Fatal(err)
		}
		oldIn, oldOut := os.Stdin, os.Stdout
		os.Stdin, os.Stdout = inRead, outWrite
		line := box.throughTheStub(t, stub, commandLine)
		code, runErr := proc.RunAsAccount(box.account, box.password, line, root,
			append(os.Environ(), proc.EnvConsoleRelay+"=1"))
		if err := outWrite.Close(); err != nil {
			t.Fatal(err)
		}
		stdout, readErr := io.ReadAll(outRead)
		os.Stdin, os.Stdout = oldIn, oldOut
		_ = inRead.Close()
		_ = outRead.Close()
		if runErr != nil {
			t.Fatalf("running through the account and stub: %v", runErr)
		}
		if code != 0 {
			t.Fatalf("the relayed run ended with exit code %d", code)
		}
		if readErr != nil {
			t.Fatalf("reading the captured stdout pipe: %v", readErr)
		}
		return string(stdout)
	}

	// The output leg: what the child writes to its own console comes back
	// as rendered VT on the run's stdout.
	const marker = "WUSERBOX-RELAY-E2E"
	stdout := relayed(`cmd.exe /c echo `+marker+`> CON`, "")
	if !strings.Contains(stdout, marker) {
		t.Errorf("the relayed console's output never named the marker; captured:\n%s", stdout)
	}

	// The input leg: a line fed to the run's stdin crosses the stub's
	// pump into the console's input, and the program reads it there. The
	// answer lands in a file, so the assertion does not depend on how the
	// console echoed the line back.
	answerFile := filepath.Join(root, "relay-stdin-answer.txt")
	stdout = relayed(fmt.Sprintf(`powershell.exe -NoProfile -Command "$v = Read-Host; Set-Content -LiteralPath '%s' -Value $v"`, answerFile), "from-relay-stdin\r\n")
	raw, err := os.ReadFile(answerFile)
	if err != nil {
		t.Fatalf("the relayed program wrote no answer (captured stdout:\n%s): %v", stdout, err)
	}
	if got := strings.TrimSpace(string(raw)); got != "from-relay-stdin" {
		t.Errorf("the program read %q from the relayed console, want the line the run fed its stdin", got)
	}
}
