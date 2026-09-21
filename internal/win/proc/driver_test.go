package proc

// The processes this package's tests re-exec themselves as -- the driver
// that plays wuserbox, and the console holder whose windowless console
// takeAConsole borrows -- and the waiting that goes with them.
// signal.Notify and console attachment are process-wide, so a test that
// wants to interrupt a run has to have a real second process to interrupt;
// everything here exists to build those processes, talk to them through
// files, and know when they are gone. What the tests then measure -- and
// what was learned the hard way about console control events -- is in
// interrupt_test.go.

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
	driverMiddle = "WUSERBOX_PROC_TEST_MIDDLE"

	ctrlBreakEvent = 1
)

var (
	procFreeConsole       = w32.Kernel32.NewProc("FreeConsole")
	procAttachConsole     = w32.Kernel32.NewProc("AttachConsole")
	procGenerateCtrlEvent = w32.Kernel32.NewProc("GenerateConsoleCtrlEvent")
	procGetConsoleWindow  = w32.Kernel32.NewProc("GetConsoleWindow")
)

// takeAConsole gives this test process a console of its own, and never
// puts a window on the screen for it.
//
// The console is needed: GenerateConsoleCtrlEvent reaches the processes
// attached to a console, and a caller attached to none can call it, get a
// success return, and signal nobody. The window is not needed by anything,
// and a test run that opens four of them across the package is a test run
// that takes the screen away from whoever started it.
//
// The window is not hidden; it is never created. The harness this replaces
// allocated its own console with AllocConsole and hid the handle it left
// behind, and that raced conhost every time: the window of an allocated
// console is created and shown by conhost, a process of its own, and
// AllocConsole returns as soon as the caller is attached -- the show then
// proceeds on conhost's own schedule, so the test's ShowWindow(SW_HIDE)
// either arrived after a flash and a stolen foreground that hiding never
// gave back, or was overridden by the show still to come. So the console is
// borrowed from a holder instead: this test binary re-execs itself as
// holdConsole, started with CREATE_NO_WINDOW, which hands the holder a real
// console with no window at all (measured -- see the createNoWindow comment
// in job.go and section 5 of docs/investigations/2026-09-20-same-window-console.md),
// and this process attaches to the holder's console. A console with no
// window gives conhost nothing to show, so there is no race to lose.
//
// It is still a whole console. The close test
// TestTakingAConsoleNeverPutsAWindowOnTheScreen delivers a CTRL_BREAK_EVENT
// through the windowless console and watches it arrive, because a console
// that cannot deliver an event is not a console.
//
// Freeing this process's own console first and attaching second, before the
// driver is started, so the driver inherits this console rather than getting
// an implicit one of its own -- see the long note at the top of
// interrupt_test.go for why that order is not optional.
func takeAConsole(t *testing.T) {
	t.Helper()
	procFreeConsole.Call()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	holder := exec.Command(exe, consoleHolderFlag)
	holder.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	if err := holder.Start(); err != nil {
		t.Fatalf("starting the console holder: %v", err)
	}
	// Registered before anything below can fail, so no path out of here
	// leaves the holder behind -- the lesson driverCommand's comment records
	// about drivers found still running hours later. Killing something
	// already gone is harmless. Registered here rather than by the caller,
	// so it also runs after driverCommand's own cleanup has killed the
	// driver: the console the driver inherited is taken away only once
	// nothing needs it.
	t.Cleanup(func() {
		_ = holder.Process.Kill()
	})

	// Not attachable the instant Start returns: the holder's console is
	// stood up during its startup by conhost, another process, and measured
	// on this machine AttachConsole called straight after Start answers
	// ERROR_INVALID_HANDLE because the console is not there yet. A bounded
	// wait, then, not an unconditional call -- the same patience
	// waitForFile shows the driver's readiness marker, generous because
	// nothing here is a measurement of how fast a machine starts a program.
	deadline := time.Now().Add(90 * time.Second)
	for {
		r, _, callErr := procAttachConsole.Call(uintptr(holder.Process.Pid))
		if r != 0 {
			break
		}
		if !time.Now().After(deadline) {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		t.Fatalf("AttachConsole(%d): %v", holder.Process.Pid, callErr)
	}

	// The structural fix, asserted where it can be enforced: the console
	// this process now shares with the holder has no window, so there is
	// nothing on the screen and nothing ever to hide. Nonzero here would
	// mean the whole point failed.
	if window, _, _ := procGetConsoleWindow.Call(); window != 0 {
		t.Fatalf("GetConsoleWindow after attaching to the holder: 0x%x -- the console was supposed to have no window", window)
	}
}

// holdConsole is the other program this test binary can be: the owner of the
// windowless console takeAConsole attaches to. It holds its console by
// staying alive and doing nothing; the console exists for exactly as long
// as it does, and nobody attached to it needs it to answer.
//
// takeAConsole's cleanup kills it when the test ends. The bound below is
// only for the test binary itself dying without its cleanups -- the same
// shape as the drivers found still running hours later that driverCommand's
// comment records.
func holdConsole() {
	time.Sleep(10 * time.Minute)
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

	// A handler that outlives the run, and is never taken down.
	//
	// The tests press again every 300ms until the driver is seen to have
	// ended, because two events sent back to back can arrive more than two
	// seconds apart under load. That leaves a window: once Run returns it
	// takes its own handler down with it, and the next event in that window
	// is handled by Windows instead, which ends this process with
	// STATUS_CONTROL_C_EXIT. Measured on CI as a driver that "failed" with
	// exactly that code after doing everything it was asked and writing its
	// report. Keeping a handler installed leaves this process its own master
	// for as long as it is alive, which is what a real wuserbox is too.
	ignored := make(chan os.Signal, 16)
	signal.Notify(ignored, os.Interrupt)

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
	// Orthogonal to the mode, because the question it asks is: does any of the
	// above still hold with one more process in the chain? See middle_test.go.
	if os.Getenv(driverMiddle) == "1" {
		commandLine = middleLine(commandLine)
	}

	type outcome struct {
		code int
		err  error
	}
	results := make(chan outcome, 1)
	go func() {
		code, err := Run(token, commandLine, dir)
		results <- outcome{code, err}
	}()

	// Generous, and for a reason worth naming: ten seconds was enough until
	// the account tests made `go test ./...` heavy enough to contend with
	// this package, and then a PowerShell that simply had not been scheduled
	// yet was reported as a boundary that did not hold. Nothing here is a
	// measurement of how fast a machine starts a program; what is measured
	// begins below, once it has.
	if !waitForPid(gcPidFile, 60*time.Second) {
		report("error: the grandchild never reported its pid")
		return
	}
	// The clock for "was it stopped, or did it just finish" starts here and
	// not at the launch above, so that a slow start cannot be mistaken for a
	// run that went the distance.
	started := time.Now()

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
// signaled readiness while the file was still empty, and the test reading it
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
	// A driver in "killable" mode waits forever on purpose, and every test
	// here ends its own driver on the way through. None of that runs when a
	// test fails first: a t.Fatal between starting the driver and ending it
	// left a process waiting forever, holding the test binary open, and three
	// of them were found still running hours later. Killing something already
	// gone is harmless, so this is registered at the start rather than made
	// conditional on how the test ends.
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
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
