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
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
)

const probeFlag = "-wuserbox-exec-probe-shielded"

// A group nothing on the machine is a member of, the same trick
// internal/win/proc's own tests use: what matters here is that Stub can
// build a token from it, never what the group itself reaches.
const nobodysGroup = "S-1-5-21-1111111111-2222222222-3333333333-727272"

// TestMain lets `go test` re-exec this binary to run the probe in a process
// of its own.
func TestMain(m *testing.M) {
	// The gated child of the launch-phase close test is this binary again,
	// dispatched by argument; it must come ahead of the driver check below
	// because the child inherits the driver's environment, driver variable
	// included.
	if len(os.Args) > 3 && os.Args[1] == gateChildFlag {
		os.Exit(runGateChild(os.Args[2], os.Args[3]))
	}
	// The fixture children of the account-seated shut tests are this binary
	// again, dispatched by argument and started as the fixture account; like
	// the gate child they sit ahead of the driver check, because they inherit
	// the driver's environment too. The exit code is the verdict and the work
	// directory argument is where the diagnosis file is written.
	if len(os.Args) > 2 && os.Args[1] == relayFixtureFlag {
		os.Exit(relayFixture(os.Args[2]))
	}
	if len(os.Args) > 2 && os.Args[1] == birthFixtureFlag {
		os.Exit(birthFixture(os.Args[2]))
	}
	if len(os.Args) > 1 && os.Args[1] == probeFlag {
		os.Exit(runProbe())
	}
	if os.Getenv(traceDriverEnv) == "1" {
		os.Exit(runTraceDriver())
	}
	os.Exit(m.Run())
}

// runProbe calls Stub exactly as --init's own probe does: a group, a read
// group, and no command line. Once Stub returns it asks proc.Shielded
// whether this process is carrying the list Shield installs.
//
// It used to ask a different question -- whether the process could still
// open itself by its own pid -- and that question has a second answer
// nobody wants: an administrator holding SeDebugPrivilege opens any process
// whatever its list says. So the old probe reported one thing on an ordinary
// desk and the opposite on an elevated CI runner, for the same correctly
// shielded process, and the test failed there having passed here. Reading
// the list itself has one answer on both.
func runProbe() int {
	if err := Stub([]string{nobodysGroup, ""}); err != nil {
		fmt.Fprintln(os.Stderr, "probe: Stub:", err)
		return 90
	}
	shielded, err := proc.Shielded()
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe: reading this process's own list:", err)
		return 91
	}
	if shielded {
		return 1 // Shield ran
	}
	return 0 // Shield did not run
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
		t.Fatal("the probe's own permission list was still the ordinary one after Stub returned with " +
			"no command line, so proc.Shield never ran -- --init would report a sandbox working when a " +
			"real run's own Shield call could still fail")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("the probe subprocess failed in an unexpected way: %v", err)
	}
	if code := exitErr.ExitCode(); code != 1 {
		t.Fatalf("the probe subprocess reported %d, not the protected list Shield having run would leave", code)
	}
}
