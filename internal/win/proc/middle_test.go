// The programs this binary can be besides a test, and what holds once one of
// them stands between a run and the program it was asked for.
//
// A run is one process deeper than it used to be. wuserbox starts as the
// sandbox's account, and what it starts is wuserbox again, which narrows its
// own token and starts the program under that -- see
// internal/sandbox/exec/stub.go. So there are two job objects now, one inside
// the other, and two processes waiting on an interrupt instead of one. Both
// properties the single-process chain had are re-measured here through that
// shape: the program's exit code comes back, one interrupt is still left to
// the program, and insisting still ends everything.
//
// The middle is modeled rather than imported. The real one is in a package
// that imports this one, and what it adds on top of Run -- a narrower token
// -- changes what the program may touch, not how a console event or a job
// reaches it.

package proc

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

const (
	sleeperFlag       = "-wuserbox-sleeper"
	middleFlag        = "-wuserbox-middle"
	prowlerFlag       = "-wuserbox-prowler"
	stubbyFlag        = "-wuserbox-stubby"
	consoleHolderFlag = "-wuserbox-console-holder"

	// A group nothing on the machine is a member of. What matters below is
	// the restricting list and the two tokens' relationship, never what the
	// group itself reaches.
	nobodysGroup = "S-1-5-21-1111111111-2222222222-3333333333-717171"
)

// TestMain lets `go test` re-exec this same binary as one of the processes
// these tests need around them: the driver that plays wuserbox, the middle
// that plays the stub, the program at the end of the chain, or the console
// holder whose windowless console takeAConsole borrows. Everything they run
// is that process's own program, not a test.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == sleeperFlag {
		sleeper(os.Args[2])
		return
	}
	if len(os.Args) > 2 && os.Args[1] == middleFlag {
		os.Exit(middle(os.Args[2]))
	}
	if len(os.Args) > 2 && os.Args[1] == prowlerFlag {
		os.Exit(prowl(os.Args[2]))
	}
	if len(os.Args) > 1 && os.Args[1] == stubbyFlag {
		os.Exit(stubby())
	}
	if len(os.Args) > 1 && os.Args[1] == consoleHolderFlag {
		holdConsole()
		return
	}
	if len(os.Args) > 2 && os.Args[1] == raceVictimFlag {
		os.Exit(raceVictim(os.Args[2]))
	}
	if len(os.Args) > 2 && os.Args[1] == stdinBridgeProbeFlag {
		os.Exit(stdinBridgeProbe(os.Args[2]))
	}
	if os.Getenv(driverEnv) == "1" {
		runDriver()
		return
	}
	os.Exit(m.Run())
}

// sleeper stands in for a program that handles Ctrl+C itself and carries on:
// an agent stopping the turn it is in, a shell clearing its line. It is what
// makes it possible to tell "the keypress reached the program" apart from
// "the run was ended".
//
// It says so as well as surviving. Staying alive proves only that nothing
// killed it, and through two jobs and two other interrupt handlers the
// question worth answering is whether the keypress arrived at all.
func sleeper(pidFile string) {
	heard := make(chan os.Signal, 4)
	signal.Notify(heard, os.Interrupt)
	go func() {
		<-heard
		_ = os.WriteFile(heardFile(pidFile), []byte("heard"), 0o600)
	}()
	_ = os.WriteFile(pidFile, []byte(fmt.Sprint(os.Getpid())), 0o600)
	time.Sleep(30 * time.Second)
}

// heardFile is where the program at the end of the chain says the interrupt
// reached it.
func heardFile(pidFile string) string { return pidFile + ".heard" }

// middle stands in for the stub: it starts the real program in a job of its
// own, waits for it exactly as a run waits out here, and ends on the
// program's own exit code.
func middle(commandLine string) int {
	var own syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		fmt.Fprintln(os.Stderr, "middle: opening its own token:", err)
		return 90
	}
	defer own.Close()
	here, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "middle:", err)
		return 91
	}
	code, err := Run(own, commandLine, here)
	if err != nil {
		fmt.Fprintln(os.Stderr, "middle: starting the program:", err)
		return 92
	}
	return code
}

// middleLine wraps a command line in the middle, the way exec.StubLine wraps
// one in the stub.
func middleLine(commandLine string) string {
	exe, err := os.Executable()
	if err != nil {
		return commandLine // nothing to wrap it in; the caller measures the plain chain
	}
	return syscall.EscapeArg(exe) + " " + middleFlag + " " + syscall.EscapeArg(commandLine)
}

// middleDriver starts the driver with the middle in the chain. The mode still
// says what the program at the end does and how the driver waits for it; this
// says only that there is one more process in between.
func middleDriver(t *testing.T, mode, dir, resultFile string) *exec.Cmd {
	t.Helper()
	cmd := driverCommand(t, mode, dir, resultFile)
	cmd.Env = append(cmd.Env, driverMiddle+"=1")
	return cmd
}

// TestTheProgramsExitCodeComesBackThroughTheMiddle is the property a run
// cannot do without: `wuserbox go test` has to fail when the tests fail, and
// with the stub in the chain the code is read twice and handed on twice
// before anything sees it.
//
// 7 rather than 1, because 1 is what half the things that go wrong in between
// report on their own.
