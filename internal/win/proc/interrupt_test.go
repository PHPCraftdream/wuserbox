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
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

const (
	driverEnv    = "WUSERBOX_PROC_TEST_HELPER"
	driverMode   = "WUSERBOX_PROC_TEST_MODE"
	driverDir    = "WUSERBOX_PROC_TEST_DIR"
	driverResult = "WUSERBOX_PROC_TEST_RESULT"

	ctrlBreakEvent = 1
)

var (
	procFreeConsole       = w32.Kernel32.NewProc("FreeConsole")
	procAllocConsole      = w32.Kernel32.NewProc("AllocConsole")
	procGenerateCtrlEvent = w32.Kernel32.NewProc("GenerateConsoleCtrlEvent")
)

// TestMain lets `go test` re-exec this same binary as the driver process
// these tests need. Everything below this check is that driver's own
// program, not a test.
const sleeperFlag = "-wuserbox-sleeper"

// sleeper stands in for a program that handles Ctrl+C itself and carries on:
// an agent stopping the turn it is in, a shell clearing its line. It is what
// makes it possible to tell "the keypress reached the program" apart from
// "the run was ended".
func sleeper(pidFile string) {
	heard := make(chan os.Signal, 4)
	signal.Notify(heard, os.Interrupt)
	_ = os.WriteFile(pidFile, []byte(fmt.Sprint(os.Getpid())), 0o600)
	time.Sleep(30 * time.Second)
}

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == sleeperFlag {
		sleeper(os.Args[2])
		return
	}
	if os.Getenv(driverEnv) == "1" {
		runDriver()
		return
	}
	os.Exit(m.Run())
}

// runDriver plays the wuserbox-parent role: it starts the sandboxed
// child+grandchild through Run, signals readiness, then either waits to be
// interrupted ("interrupt" mode) or waits to be killed outright ("killable"
// mode). Its findings go to a result file; in "killable" mode there is no
// controlled exit at all, so nothing past the kill can rely on running.
func runDriver() {
	mode := os.Getenv(driverMode)
	dir := os.Getenv(driverDir)
	resultFile := os.Getenv(driverResult)
	report := func(msg string) { _ = os.WriteFile(resultFile, []byte(msg), 0o600) }

	gcPidFile := filepath.Join(dir, "grandchild.pid")
	readyFile := filepath.Join(dir, "ready.marker")

	var token syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &token); err != nil {
		report("error opening this process's own token: " + err.Error())
		return
	}
	defer token.Close()

	// cmd.exe is the child Run() assigns to the job; the powershell it
	// launches is the grandchild -- something the child started, never
	// assigned to the job directly, reached only because the job reaches
	// everything a member starts. Waiting for the grandchild's own pid file
	// below is what proves it, not cmd.exe, is actually running before
	// either test moves on -- cmd.exe reaching its "&&" proves nothing about
	// whether powershell has been loaded and scheduled yet.
	commandLine := `C:\Windows\System32\cmd.exe /c powershell -NoProfile -Command "$PID | Out-File -Encoding ascii '` +
		gcPidFile + `'; Start-Sleep -Seconds 60"`
	if mode == "patient" {
		// A program that hears the interrupt and carries on, so that the
		// keypress reaching it can be told apart from the run being ended.
		exe, err := os.Executable()
		if err != nil {
			report("error finding this binary: " + err.Error())
			return
		}
		commandLine = syscall.EscapeArg(exe) + " " + sleeperFlag + " " + syscall.EscapeArg(gcPidFile)
	}

	type outcome struct {
		code int
		err  error
	}
	results := make(chan outcome, 1)
	started := time.Now()
	go func() {
		code, err := Run(token, commandLine, dir)
		results <- outcome{code, err}
	}()

	if !waitForPid(gcPidFile, 10*time.Second) {
		report("error: the grandchild never reported its pid")
		return
	}

	switch mode {
	case "patient":
		_ = os.WriteFile(readyFile, []byte("ready"), 0o600)
		select {
		case o := <-results:
			report(fmt.Sprintf("ended code=%d runerr=%v", o.code, o.err))
		case <-time.After(30 * time.Second):
			report("still running")
		}
	case "interrupt":
		_ = os.WriteFile(readyFile, []byte("ready"), 0o600)
		select {
		case o := <-results:
			elapsed := time.Since(started).Milliseconds()
			if o.err != nil {
				report(fmt.Sprintf("ok code=%d runerr=%v elapsed_ms=%d", o.code, o.err, elapsed))
			} else {
				report(fmt.Sprintf("ok code=%d elapsed_ms=%d", o.code, elapsed))
			}
		case <-time.After(30 * time.Second):
			report("error: Run did not return within 30s of the interrupt")
		}

	case "killable":
		_ = os.WriteFile(readyFile, []byte("ready"), 0o600)
		// Deliberately no cleanup past this point: the test kills this
		// process outright, the way a real kill would, and nothing here
		// gets to run in response.
		select {}

	default:
		report("error: unknown mode " + mode)
	}
}

// waitForPid waits for a pid file to hold a pid, which is not the same as
// waiting for it to exist. PowerShell's Out-File creates the file and writes
// into it afterwards, so a driver that moved on at the first sight of it
// signalled readiness while the file was still empty, and the test reading it
// got "" where it wanted a number. Every use of the marker wants the pid, so
// the wait is for the pid.
func waitForPid(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if raw, err := os.ReadFile(path); err == nil {
			if _, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitForFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// driverCommand starts this same test binary as the driver, in its own
// console process group. That group's id is then the driver's own pid,
// known to the caller without having to ask the OS for it -- which is what
// lets GenerateConsoleCtrlEvent below address the driver precisely.
func driverCommand(t *testing.T, mode, dir, resultFile string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(),
		driverEnv+"=1",
		driverMode+"="+mode,
		driverDir+"="+dir,
		driverResult+"="+resultFile,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func readReport(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no result written: %v", err)
	}
	return string(raw)
}

func readPid(t *testing.T, path string) uint32 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the grandchild never reported its pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("bad pid %q: %v", raw, err)
	}
	return uint32(pid)
}

func elapsedMS(t *testing.T, report string) int64 {
	t.Helper()
	const key = "elapsed_ms="
	idx := strings.Index(report, key)
	if idx < 0 {
		t.Fatalf("no %s in report: %s", key, report)
	}
	rest := report[idx+len(key):]
	if end := strings.IndexAny(rest, " \n"); end >= 0 {
		rest = rest[:end]
	}
	ms, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
	if err != nil {
		t.Fatalf("bad %s in %q: %v", key, report, err)
	}
	return ms
}

// processGone waits, bounded, for pid to no longer exist. Failing to open
// it at all counts as gone: that is what a pid nothing holds a handle to
// anymore looks like just as much as a signaled handle does.
func processGone(t *testing.T, pid uint32, timeout time.Duration) bool {
	t.Helper()
	handle, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, pid)
	if err != nil {
		return true
	}
	defer syscall.CloseHandle(handle)
	deadline := time.Now().Add(timeout)
	for {
		event, err := syscall.WaitForSingleObject(handle, 200)
		if err != nil || event == syscall.WAIT_OBJECT_0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

func waitDriver(t *testing.T, cmd *exec.Cmd, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("driver process: %v", err)
		}
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		t.Fatal("driver process did not finish in time")
	}
}

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
	procFreeConsole.Call()
	if r, _, callErr := procAllocConsole.Call(); r == 0 {
		t.Fatalf("AllocConsole: %v", callErr)
	}

	cmd := driverCommand(t, "interrupt", dir, resultFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitForFile(readyFile, 15*time.Second) {
		_ = cmd.Process.Kill()
		t.Fatal("driver never became ready")
	}

	// Sent to the driver's own console process group id -- its pid, since
	// it was started with CREATE_NEW_PROCESS_GROUP above -- twice in a row:
	// an interrupt arriving while the first is still being handled must not
	// change the outcome.
	pid := uint32(cmd.Process.Pid)
	if r, _, callErr := procGenerateCtrlEvent.Call(ctrlBreakEvent, uintptr(pid)); r == 0 {
		t.Fatalf("GenerateConsoleCtrlEvent: %v", callErr)
	}
	procGenerateCtrlEvent.Call(ctrlBreakEvent, uintptr(pid))

	waitDriver(t, cmd, 45*time.Second)

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

	if !waitForFile(readyFile, 15*time.Second) {
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

	procFreeConsole.Call()
	if r, _, callErr := procAllocConsole.Call(); r == 0 {
		t.Fatalf("AllocConsole: %v", callErr)
	}

	cmd := driverCommand(t, "patient", dir, resultFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	if !waitForFile(filepath.Join(dir, "ready.marker"), 20*time.Second) {
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
