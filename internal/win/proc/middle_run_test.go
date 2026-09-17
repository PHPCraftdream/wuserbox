// What holds once a middle stands between a run and its program: the exit
// code still comes back, one interrupt is still left to the program, and
// insisting still ends everything. The machinery these drive is in
// middle_test.go; the doors they check afterwards are in prowler_test.go.

package proc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

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

// TestTheProgramCannotTurnOnTheProcessThatConfinedIt is the question the
// two-process chain raises and nothing else here answers.
//
// The stub and the program it starts are the same account. The stub holds
// that account's ordinary token; the program holds the restricted one. If the
// program can reach the stub's process object it can take the stub's token,
// wear it -- impersonating a token of one's own user needs no privilege -- and
// the second access check is gone. The file boundary would then be a
// formality, undone from inside without touching a single file permission.
//
// Measured on the shape rather than on a real account, because the shape is
// the whole of it: one process holding an unrestricted token, a second
// holding a token restricted from it, both the same user, and that user's own
// identifier among the restricting ones -- which is exactly what
// token.AsSandbox arranges and what makes an MSYS program start at all.
//
// The stand-in in the middle is what does the restricting, so nothing here
// touches the test binary's own token or its own permissions. That matters:
// restricting this process's token and naming this process's own user is the
// move token.AsSandbox's comment calls catastrophic in the other direction,
// and it is right.
func TestTheProgramCannotTurnOnTheProcessThatConfinedIt(t *testing.T) {
	var own syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	code, err := Run(own, syscall.EscapeArg(exe)+" "+stubbyFlag, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if code&middleBroke != 0 {
		t.Fatalf("the stand-in for the stub failed before it could be turned on: %d", code&^middleBroke)
	}
	if code&openedItself == 0 {
		t.Fatal("the program could not open its own process, so the shutting went too far " +
			"and what follows would pass for the wrong reason")
	}
	if reached := code &^ openedItself; reached != 0 {
		t.Errorf("a program under the restricted token reached the process that restricted it: %s",
			doorsReached(reached))
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

	takeAConsole(t)

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

	takeAConsole(t)

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
