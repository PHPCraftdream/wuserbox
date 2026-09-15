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
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	sleeperFlag = "-wuserbox-sleeper"
	middleFlag  = "-wuserbox-middle"
)

// TestMain lets `go test` re-exec this same binary as one of the processes
// these tests need around them: the driver that plays wuserbox, the middle
// that plays the stub, or the program at the end of the chain. Everything
// they run is that process's own program, not a test.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == sleeperFlag {
		sleeper(os.Args[2])
		return
	}
	if len(os.Args) > 2 && os.Args[1] == middleFlag {
		os.Exit(middle(os.Args[2]))
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
func TestTheProgramsExitCodeComesBackThroughTheMiddle(t *testing.T) {
	var own syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()

	code, err := Run(own, middleLine(`C:\Windows\System32\cmd.exe /c exit 7`), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Errorf("the run ended with %d, and the program it ran ended with 7", code)
	}
}

// TestOneInterruptStillReachesTheProgramThroughTheMiddle is the decision that
// a single Ctrl+C belongs to the program, held with two more things in its
// way: the middle's own console control handler, and the middle's own job.
//
// Neither is allowed to swallow it. Almost everything that runs in a sandbox
// treats the first one as its own business -- an agent stops the turn it is
// in, a shell clears its line -- and a run that ended there would kill the
// agent where the person meant to interrupt it.
func TestOneInterruptStillReachesTheProgramThroughTheMiddle(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "result.txt")
	pidFile := filepath.Join(dir, "grandchild.pid")

	procFreeConsole.Call()
	if r, _, callErr := procAllocConsole.Call(); r == 0 {
		t.Fatalf("AllocConsole: %v", callErr)
	}

	cmd := middleDriver(t, "patient", dir, resultFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitForFile(filepath.Join(dir, "ready.marker"), 90*time.Second) {
		t.Fatal("the driver never became ready")
	}
	pid := readPid(t, pidFile)

	if r, _, callErr := procGenerateCtrlEvent.Call(ctrlBreakEvent, uintptr(cmd.Process.Pid)); r == 0 {
		t.Fatalf("GenerateConsoleCtrlEvent: %v", callErr)
	}

	// Ten and not more: the program at the end sleeps for thirty seconds and
	// then ends on its own, which would look exactly like the run being
	// ended. Delivering a console event takes milliseconds, so a wait long
	// enough to eat that margin would only ever turn one failure into
	// another.
	if !waitForFile(heardFile(pidFile), 10*time.Second) {
		t.Error("the interrupt never reached the program at the end of the chain")
	}
	// Long enough that an ending would have happened by now.
	time.Sleep(1500 * time.Millisecond)

	if _, err := os.Stat(resultFile); err == nil {
		t.Errorf("one interrupt ended the run: %s", readReport(t, resultFile))
	}
	if processGone(t, pid, 200*time.Millisecond) {
		t.Error("one interrupt killed a program that was handling it itself")
	}
}

// TestInsistingStillEndsTheRunThroughTheMiddle is the other half: a second
// interrupt, arriving while the first is still recent, ends everything --
// through a program that would otherwise sleep out its thirty seconds, and
// through a job inside a job.
func TestInsistingStillEndsTheRunThroughTheMiddle(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "result.txt")
	pidFile := filepath.Join(dir, "grandchild.pid")

	procFreeConsole.Call()
	if r, _, callErr := procAllocConsole.Call(); r == 0 {
		t.Fatalf("AllocConsole: %v", callErr)
	}

	cmd := middleDriver(t, "patient", dir, resultFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitForFile(filepath.Join(dir, "ready.marker"), 90*time.Second) {
		t.Fatal("the driver never became ready")
	}
	pid := readPid(t, pidFile)

	// Kept up until the run ends rather than pressed exactly twice: Windows
	// delivers each console control event on a thread it creates in the
	// target, so under load two sent back to back can arrive more than two
	// seconds apart, and the second then counts as a new first. Somebody
	// insisting presses again; so does this.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(300 * time.Millisecond):
				procGenerateCtrlEvent.Call(ctrlBreakEvent, uintptr(cmd.Process.Pid))
			}
		}
	}()
	waitDriver(t, cmd, 90*time.Second)
	close(stop)

	report := readReport(t, resultFile)
	if want := fmt.Sprintf("ended code=%d", uint32(statusControlCExit)); !strings.HasPrefix(report, want) {
		t.Errorf("the driver reported %q, and the run should have ended saying it was stopped", report)
	}
	if !processGone(t, pid, 5*time.Second) {
		t.Errorf("the program (pid %d) is still running after the run was ended", pid)
	}
}
