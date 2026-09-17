package proc

// These tests measure the two ways a run can be stopped from outside
// itself: an interrupt caught by this process, and this process being
// killed outright. Both need a real second process -- signal.Notify and
// console attachment are process-wide -- so this binary re-execs itself
// (TestMain below intercepts that) to play "wuserbox" in a process the test
// can signal or kill from the outside, the way an operator would.
//
// Measured while building this:
//
//   - GenerateConsoleCtrlEvent(CTRL_C_EVENT, pid) -- the naive way to target
//     one specific process -- delivers nothing to a process started with
//     CREATE_NEW_PROCESS_GROUP, because such a process is documented to
//     ignore CTRL_C_EVENT regardless of how it is addressed. CTRL_BREAK_EVENT
//     is not ignored, and Go's runtime maps both events to the same
//     os.Interrupt (see runtime/os_windows.go), so sending CTRL_BREAK_EVENT
//     exercises exactly the code path a real Ctrl+C would -- the same
//     mechanism the Go standard library's own os/signal windows test uses
//     (signal_windows_test.go, TestCtrlBreak): a target in its own process
//     group, addressed by that group's id, which is its own pid.
//
//   - The caller of GenerateConsoleCtrlEvent needs a console of its own for
//     a targeted event to reach anywhere: a caller attached to no console at
//     all (true of this test binary, launched by a shell that gives it none)
//     can call it, get a success return, and have it reach nobody -- signaling
//     an empty console, exactly the trap the task named. FreeConsole then
//     AllocConsole, done by the test *before* starting the driver so the
//     driver inherits the same console rather than getting an implicit one
//     of its own, fixes this.
//
//   - That allocation has to happen in the test, not in the driver: a
//     process's own registered console control handler -- which is what
//     lets the driver's signal.Notify(os.Interrupt) catch anything at all --
//     stops being effective for events sent after that same process frees
//     and reallocates its own console. Measured directly: a process signals
//     its own group with CTRL_BREAK_EVENT and catches it via signal.Notify
//     when it never touched its own console, and is instead torn down by the
//     OS's default action (STATUS_CONTROL_C_EXIT, unseen by signal.Notify)
//     when it called FreeConsole/AllocConsole on itself first.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRunStopsOnInterruptAndWhatItStarted proves the two properties that
// used to depend on the console alone, and are no longer relied upon to
// cross an account boundary that might not carry them: an interrupt stops
// the sandboxed program and whatever it started, and the exit code
// afterwards says so rather than reporting success.
func TestRunStopsOnInterruptAndWhatItStarted(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "result.txt")
	gcPidFile := filepath.Join(dir, "grandchild.pid")
	readyFile := filepath.Join(dir, "ready.marker")

	// Before starting the driver, not after: taken later, this would be a
	// fresh, empty console while the driver is still attached to whatever
	// this test process had (here, none), and GenerateConsoleCtrlEvent
	// below would address a console with nobody on it.
	takeAConsole(t)

	cmd := driverCommand(t, "interrupt", dir, resultFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitForFile(readyFile, 90*time.Second) {
		_ = cmd.Process.Kill()
		t.Fatal("driver never became ready")
	}

	// Sent to the driver's own console process group id -- its pid, since it
	// was started with CREATE_NEW_PROCESS_GROUP above.
	pid := uint32(cmd.Process.Pid)
	if r, _, callErr := procGenerateCtrlEvent.Call(ctrlBreakEvent, uintptr(pid)); r == 0 {
		t.Fatalf("GenerateConsoleCtrlEvent: %v", callErr)
	}
	// And kept up until the run ends, rather than pressed exactly twice and
	// hoped for. What ends the run is a second interrupt the driver *observes*
	// within two seconds of the first, and observing one is not the same as
	// sending it: Windows delivers each console control event on a thread it
	// creates in the target, so under load -- the whole suite at once -- two
	// sent back to back can arrive more than two seconds apart, and the second
	// then counts as a new first. That made this test fail while the behavior
	// it tests was working. Somebody insisting presses again; so does this.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(300 * time.Millisecond):
				procGenerateCtrlEvent.Call(ctrlBreakEvent, uintptr(pid))
			}
		}
	}()

	waitDriver(t, cmd, 90*time.Second)
	close(stop)

	report := readReport(t, resultFile)
	if !strings.HasPrefix(report, "ok ") {
		t.Fatalf("driver reported: %s", report)
	}
	if want := fmt.Sprintf("code=%d", statusControlCExit); !strings.Contains(report, want) {
		t.Errorf("exit code did not say the run was stopped rather than succeeded: %s", report)
	}
	// The grandchild sleeps for 60s; returning in a fraction of that is the
	// difference between being stopped and running to completion.
	if ms := elapsedMS(t, report); ms > 20000 {
		t.Errorf("took %dms -- looks like it ran to completion instead of being stopped", ms)
	}

	gcPid := readPid(t, gcPidFile)
	if !processGone(t, gcPid, 5*time.Second) {
		t.Errorf("the grandchild (pid %d) is still running after the interrupt stopped the run", gcPid)
	}
}

// TestKillOnCloseStopsEverythingIfWuserboxIsKilledOutright proves the other
// half: wuserbox itself can be killed outright, with none of its own code
// -- including the interrupt handling above -- getting a chance to run,
// and the job's kill-on-close still has to end what it started.
func TestKillOnCloseStopsEverythingIfWuserboxIsKilledOutright(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "result.txt")
	gcPidFile := filepath.Join(dir, "grandchild.pid")
	readyFile := filepath.Join(dir, "ready.marker")

	cmd := driverCommand(t, "killable", dir, resultFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	if !waitForFile(readyFile, 90*time.Second) {
		_ = cmd.Process.Kill()
		t.Fatal("driver never became ready")
	}
	pid := readPid(t, gcPidFile)

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("killing the driver outright: %v", err)
	}
	_, _ = cmd.Process.Wait()

	if !processGone(t, pid, 10*time.Second) {
		t.Errorf("the grandchild (pid %d) is still running after wuserbox was killed outright", pid)
	}
}

// TestOneInterruptIsLeftToTheProgram is the guard on the decision that a
// single Ctrl+C is not an instruction to end the run.
//
// Almost everything that runs in a sandbox treats it as its own business: an
// agent stops the turn it is in the middle of, a shell clears its line, a REPL
// abandons what was typed. Ending the job on the first one would take that
// decision away and kill the agent where the user meant to interrupt it. So
// the keypress is left to reach the program -- which is also why the child is
// not put in a process group of its own, since that would stop it arriving at
// all -- and only somebody insisting ends the run.
func TestOneInterruptIsLeftToTheProgram(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "result.txt")
	pidFile := filepath.Join(dir, "grandchild.pid")

	takeAConsole(t)

	cmd := driverCommand(t, "patient", dir, resultFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	if !waitForFile(filepath.Join(dir, "ready.marker"), 90*time.Second) {
		t.Fatal("the driver never became ready")
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("the program never reported its pid: %v", err)
	}
	var pid uint32
	if _, err := fmt.Sscanf(string(raw), "%d", &pid); err != nil {
		t.Fatalf("bad pid %q: %v", raw, err)
	}

	if r, _, callErr := procGenerateCtrlEvent.Call(ctrlBreakEvent, uintptr(cmd.Process.Pid)); r == 0 {
		t.Fatalf("GenerateConsoleCtrlEvent: %v", callErr)
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
