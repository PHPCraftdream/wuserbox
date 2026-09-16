// The regression for the second, smaller defect in this file: Stub used to
// return before proc.Shield ran whenever it had no program to start, which is
// exactly the call ProveItStarts makes for --init. A sandbox whose real runs
// would fail inside Shield could therefore be built and reported working,
// because nothing --init did ever reached the call a real run depends on.
//
// Reached through a subprocess and not in-process: Shield narrows the calling
// process's own security descriptor, and calling it from the test binary
// itself would narrow the test binary for the rest of this package's run
// rather than for one test alone.

package exec

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

const probeFlag = "-wuserbox-exec-probe-shielded"

// A group nothing on the machine is a member of, the same trick
// internal/win/proc's own tests use: what matters here is that Stub can
// build a token from it, never what the group itself reaches.
const nobodysGroup = "S-1-5-21-1111111111-2222222222-3333333333-727272"

// TestMain lets `go test` re-exec this binary to run the probe in a process
// of its own.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == probeFlag {
		os.Exit(runProbe())
	}
	os.Exit(m.Run())
}

const processQueryInformation = 0x0400

// runProbe calls Stub exactly as --init's own probe does: a group, a read
// group, and no command line. Once Stub returns, it asks whether this
// process can still open itself by its own pid -- a real access check,
// unlike the pseudo-handle every process has to itself, and the same check
// Shield's own doc names as never being checked against a list. If Shield
// ran, that access is refused; if Stub returned before Shield ran, this
// process is exactly as open as it was when it started, and the open
// succeeds.
func runProbe() int {
	if err := Stub([]string{nobodysGroup, ""}); err != nil {
		fmt.Fprintln(os.Stderr, "probe: Stub:", err)
		return 90
	}
	h, err := syscall.OpenProcess(processQueryInformation, false, uint32(os.Getpid()))
	if err != nil {
		return 1 // refused: Shield ran
	}
	syscall.CloseHandle(h)
	return 0 // opened: Shield did not run
}

// TestTheInitProbeShieldsItselfToo asks that question of today's code.
func TestTheInitProbeShieldsItselfToo(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, probeFlag)
	err = cmd.Run()
	if err == nil {
		t.Fatal("the probe could still open itself by pid after Stub returned with no command line, " +
			"so proc.Shield never ran -- --init would report a sandbox working when a real run's own " +
			"Shield call could still fail")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("the probe subprocess failed in an unexpected way: %v", err)
	}
	if code := exitErr.ExitCode(); code != 1 {
		t.Fatalf("the probe subprocess reported %d, not the refusal Shield having run would produce", code)
	}
}
