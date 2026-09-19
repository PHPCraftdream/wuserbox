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
	"os"
	"syscall"
	"testing"
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
