// Repointing the standard streams at a console the process already has.
//
// takeOwnConsole has two halves: AllocConsole makes the stub a console of
// its own, and openConsoleStreams opens CONIN$/CONOUT$ by name and points
// os.Stdin, os.Stdout and os.Stderr at it. The first half cannot be
// exercised inside a test run without putting a window on the screen of
// every test run -- AllocConsole makes a real one, and one per test is
// exactly what the createNoWindow comment in internal/win/proc/job.go
// records the cost of, windows appearing and stealing the keyboard from
// whoever is using the machine. So what is covered here is the second half,
// the open-and-repoint, which needs no allocation at all when the test
// process already has a console, as it does under `go test` from a terminal:
// the same two calls run, and the streams they install name a real console.
// The allocation half is measured end to end by internal/e2e's own-console
// test and by the live runs against a real sandbox, where the window on the
// screen is the product working rather than a test misbehaving.

package exec

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
)

// TestOpenConsoleStreamsRepointsTheStandardStreamsAtARealConsole covers the
// AllocConsole-free half of takeOwnConsole: openConsoleStreams opens the
// console devices and installs them as this process's standard streams,
// allocating nothing. Most harnesses run this binary without a console of
// its own, and there the open fails and the test skips -- the repointing has
// nothing real to be measured against, and standing a console up for it
// would put the window back on the screen.
func TestOpenConsoleStreamsRepointsTheStandardStreamsAtARealConsole(t *testing.T) {
	oldStdin, oldStdout, oldStderr := os.Stdin, os.Stdout, os.Stderr
	restore := func() { os.Stdin, os.Stdout, os.Stderr = oldStdin, oldStdout, oldStderr }
	err := openConsoleStreams()
	if err != nil {
		restore()
		t.Skipf("this test process has no console of its own to be repointed at: %v", err)
	}
	defer restore()
	// GetConsoleMode answers on the new os.Stdin: the streams now name a
	// real console, which is the whole property the stub hands the program.
	var mode uint32
	if err := syscall.GetConsoleMode(syscall.Handle(os.Stdin.Fd()), &mode); err != nil {
		t.Errorf("the repointed stdin is not a console: %v", err)
	}
}

// TestTheConsoleRelayCarriesTheChildsRenderedOutput proves the plumbing
// built here, end to end inside one process and one account: the console
// exists, the child started by the same proc.RunWithConsole the stub will
// call is born attached to it, and the child's rendered output arrives on
// the relay's output pipe as VT bytes. It does not prove the account
// crossing -- that was measured live under a real sandbox account,
// docs/investigations/2026-09-20-same-window-console.md section 4 -- and it
// does not prove the relay across the operator bridge, which is a later
// task. The child is cmd.exe; what it echoes reaches the console a real
// terminal program would see, and arrives as the same rendered VT a real
// terminal's pixels start life as.
//
// The echo goes through the console device by name rather than a standard
// handle, and that redirect is measured honesty, not a dodge: this test
// process has a console of its own (go test's), and in that shape a plain
// `echo` landed on the test harness while the relay never saw it -- measured,
// in this test's first draft, with the captured stream dumped both ways.
// What the child's own console is, is not in question: `> CON` opens the
// devices of the console the child was born attached to, which is exactly
// what a real terminal program's C runtime does when its inherited standard
// handles are unusable -- the documented CRT-startup gap. Under the real
// stub the host has no console at all (GetConsoleWindow 0x0,
// docs/investigations/2026-09-20-same-window-console.md section 4), and that
// gap is the shape the stub's child actually sits in.
func TestTheConsoleRelayCarriesTheChildsRenderedOutput(t *testing.T) {
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	relay, err := takeConsoleRelay()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.close()
	// Drained continuously from the moment the console exists: reading only
	// after the child ends would deadlock against a child whose output fills
	// the pipe before it exits -- the record internal/e2e/teardown_test.go
	// keeps for the same shape.
	var out bytes.Buffer
	var outMu sync.Mutex
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 4096)
		for {
			n, readErr := relay.output.Read(buf)
			if n > 0 {
				outMu.Lock()
				out.Write(buf[:n])
				outMu.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}()
	captured := func() string {
		outMu.Lock()
		defer outMu.Unlock()
		return out.String()
	}

	var own syscall.Token
	// The child runs under the current, same-account, unrestricted token;
	// the account crossing is not this test's business.
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()

	// Twenty-one characters, under the console's 80 columns, so the echo
	// cannot be rewrapped in half.
	const marker = "WUSERBOX-CONPTY-RELAY"
	// The echo goes through the console by name; see this test's doc comment
	// for why a standard handle would point somewhere else entirely.
	code, err := proc.RunWithConsole(own, `C:\Windows\System32\cmd.exe /c echo `+marker+`> CON`, t.TempDir(), relay.hpc)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("the child ended with exit code %d, want 0", code)
	}
	// The child is done, but its conhost renders on a timer of its own and
	// holds the last write end of the output pipe: ending the console the
	// instant the child exits can drop the rendered echo on the floor
	// (measured -- the VT startup sequences arrive, the echo does not). Wait
	// briefly for it, then close: closing the console is what lets the drain
	// reach EOF. close is safe to call twice -- the deferred call finds
	// nothing left to do.
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(captured(), marker) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	relay.close()
	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		t.Fatalf("the relay's output never reached EOF; captured so far:\n%s", captured())
	}
	if got := captured(); !strings.Contains(got, marker) {
		t.Errorf("the relay's output never named the marker; captured:\n%s", got)
	}
}

// TestAStubAskedForTwoConsolesAtOnceRefuses pins the mutual-exclusion
// policy: one program, one console, and the stub refuses the contradiction
// rather than resolving it silently. The refusal is the usage code because a
// contradictory request is a malformed request. Calling Stub in-process is
// safe here because the check sits before the token is built and before
// anything is started: it reads the two env vars and returns.
func TestAStubAskedForTwoConsolesAtOnceRefuses(t *testing.T) {
	t.Setenv(proc.EnvOwnConsole, "1")
	t.Setenv(proc.EnvConsoleRelay, "1")
	err := Stub([]string{"S-1-5-21-1-2-3-1004", "some-read-group", "cmd /c echo hi"})
	if err == nil {
		t.Fatal("the stub accepted two consoles for one program")
	}
	if got := exit.Of(err); got != exit.Usage {
		t.Errorf("the refusal carried exit code %v, want %v (usage)", got, exit.Usage)
	}
	for _, named := range []string{proc.EnvOwnConsole, proc.EnvConsoleRelay} {
		if !strings.Contains(err.Error(), named) {
			t.Errorf("the refusal does not name %s: %v", named, err)
		}
	}
}
