// The stdin bridge: what duplicateInput and noInherit do to a handle before
// it ever gets near CreateProcessWithLogonW, and -- as far as a test outside
// a real second account and administrator rights can reach -- what happens
// when os.Stdin really is a console instead of the redirected pipe every
// other test in this package and internal/e2e substitutes for it.
//
// A live, human-typed console cannot be reproduced by an autotest. A Windows
// pseudo console (ConPTY, CreatePseudoConsole, Windows 10 1809+) can stand in
// for one: this process re-execs itself attached to a pseudo console, so the
// child's own os.Stdin is console(os.Stdin) == true for the same reason a
// real interactive cmd.exe prompt is, and the child runs duplicateInput on
// it exactly as runAsAccount would. That proves the bridge carries real
// console input across a handle boundary; it does not need, and does not
// attempt, the account crossing itself, which is TestTheStreamsComeBackFromInsideTheSandbox's
// job and needs administrator rights and a real second account that this
// package's tests do not have.

package proc

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

const stdinBridgeProbeFlag = "-wuserbox-stdin-bridge-probe"

var (
	procCreatePseudoConsole  = w32.Kernel32.NewProc("CreatePseudoConsole")
	procClosePseudoConsole   = w32.Kernel32.NewProc("ClosePseudoConsole")
	procCreateProcessForPty  = w32.Kernel32.NewProc("CreateProcessW")
	procGetHandleInformation = w32.Kernel32.NewProc("GetHandleInformation")
)

// handleInheritable reads HANDLE_FLAG_INHERIT back off a handle through
// GetHandleInformation, the same call
// docs/reviews/sandbox-security-review-2026-09-19.md's suggested fix and
// internal/base/lock/slot_chain_test.go both use to turn "should not be
// inheritable" from a belief into a measurement.
func handleInheritable(t *testing.T, handle syscall.Handle) bool {
	t.Helper()
	var flags uint32
	if r, _, callErr := procGetHandleInformation.Call(uintptr(handle), uintptr(unsafe.Pointer(&flags))); r == 0 {
		t.Fatalf("GetHandleInformation: %v", callErr)
	}
	return flags&handleFlagInherit != 0
}

// TestNoInheritStripsTheInheritFlag is the handle-hygiene helper P2-1 of
// docs/reviews/sandbox-security-review-2026-09-19.md asked for, measured the
// way internal/base/lock/slot.go's own non-inheritance claim is measured
// rather than only argued in a comment.
func TestNoInheritStripsTheInheritFlag(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()

	if !handleInheritable(t, syscall.Handle(read.Fd())) {
		t.Fatal("os.Pipe()'s read end was not inheritable before noInherit ran -- " +
			"the assumption bridgePipe and duplicateInput both depend on no longer holds")
	}
	if err := noInherit(read); err != nil {
		t.Fatal(err)
	}
	if handleInheritable(t, syscall.Handle(read.Fd())) {
		t.Error("noInherit left HANDLE_FLAG_INHERIT set")
	}
}

// TestBridgePipeReadEndIsNotInheritable measures the P2-1 fix at the actual
// call site: the end bridgePipe keeps for itself must not cross into
// whatever else CreateProcessWithLogonW starts, and the end it hands out
// must still be inheritable, or the account could never read/write it at
// all.
func TestBridgePipeReadEndIsNotInheritable(t *testing.T) {
	read, handle, err := bridgePipe("test")
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer syscall.CloseHandle(handle)

	if handleInheritable(t, syscall.Handle(read.Fd())) {
		t.Error("bridgePipe's read end, which stays in this process, is still inheritable")
	}
	if !handleInheritable(t, handle) {
		t.Error("bridgePipe's returned handle, meant to cross into the account, is not inheritable")
	}
}

// TestInputBridgePipeWriteEndIsNotInheritable is
// TestBridgePipeReadEndIsNotInheritable's counterpart for the input
// direction: the write end inputBridgePipe keeps for itself, to copy the
// real console into, must not cross into the account either, and the read
// end it hands out must still be inheritable, or the account could never
// read it. Tested directly against inputBridgePipe rather than through
// duplicateInput, so this holds regardless of whether this test's own stdin
// happens to be a console.
func TestInputBridgePipeWriteEndIsNotInheritable(t *testing.T) {
	write, handle, err := inputBridgePipe()
	if err != nil {
		t.Fatal(err)
	}
	defer write.Close()
	defer syscall.CloseHandle(handle)

	if handleInheritable(t, syscall.Handle(write.Fd())) {
		t.Error("inputBridgePipe's write end, which stays in this process, is still inheritable")
	}
	if !handleInheritable(t, handle) {
		t.Error("inputBridgePipe's returned handle, meant to cross into the account, is not inheritable")
	}
}

// TestDuplicateInputLeavesARedirectedStdinAlone is the path every existing
// test in this repository already takes without knowing it: os.Stdin
// substituted with the read end of an os.Pipe() (internal/e2e/account_test.go's
// realBox.streams, TestRunForwardsStandardStreams), which is not a console.
// duplicateInput has to leave handles.input exactly as
// duplicateStandardHandles built it in that case -- a direct duplicate, no
// pipe, no goroutine -- which is what made this whole bug invisible to every
// test that existed before this file.
func TestDuplicateInputLeavesARedirectedStdinAlone(t *testing.T) {
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inWrite.Close()
	oldIn := os.Stdin
	os.Stdin = inRead
	defer func() {
		os.Stdin = oldIn
		inRead.Close()
	}()

	if console(os.Stdin) {
		t.Fatal("a pipe's read end reported itself as a console")
	}

	handles, err := duplicateStandardHandles()
	if err != nil {
		t.Fatal(err)
	}
	defer handles.close()
	before := handles.input

	bridge, err := duplicateInput(&handles)
	if err != nil {
		t.Fatal(err)
	}
	if bridge != nil {
		t.Error("duplicateInput built a bridge for a redirected (non-console) stdin")
	}
	if handles.input != before {
		t.Error("duplicateInput changed handles.input even though stdin is not a console")
	}
}

// fixupStdinFromConin compensates for a gap in this test's own plumbing, not
// in production: a process attached to a Windows pseudo console
// (CreatePseudoConsole + PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE) gets a real,
// working console -- CONIN$ opens and answers GetConsoleMode correctly,
// measured while building this test -- but GetStdHandle(STD_INPUT_HANDLE)
// keeps whatever raw, unusable value CreateProcessW happened to copy in and
// is never repointed at that console.
//
// C-runtime-linked console apps (cmd.exe, powershell.exe) never notice,
// because their own CRT startup validates GetStdHandle's answer and opens
// CONIN$/CONOUT$/CONERR$ itself when it looks unusable -- a decades-old
// piece of console bootstrapping this repository's own e2e tests never
// needed, because wuserbox is always started by an ordinary shell through
// ordinary console inheritance, which populates GetStdHandle correctly
// without any pseudo console involved. ConPTY is only this test's surrogate
// for "stdin is a console", and this particular gap belongs to that
// surrogate, not to the thing being tested. Go's runtime skips CRT startup
// entirely, so nothing does the CRT's fixup for a Go binary; this function
// is that fixup, done once, only inside the pseudo-console child this test
// starts.
func fixupStdinFromConin() {
	if console(os.Stdin) {
		return
	}
	name, err := syscall.UTF16PtrFromString("CONIN$")
	if err != nil {
		return
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return
	}
	candidate := os.NewFile(uintptr(handle), "CONIN$")
	if !console(candidate) {
		_ = candidate.Close()
		return
	}
	os.Stdin = candidate
}

// stdinBridgeProbe runs inside the pseudo-console-attached child
// TestStdinBridgeCarriesRealConsoleInput starts. Its own os.Stdin is the
// pseudo console's device side, which GetConsoleMode answers for exactly as
// it would for a real interactive prompt -- the one condition
// duplicateInput's console path exists for and nothing else in this
// repository's test suite reaches. This runs the same three calls
// runAsAccount does -- duplicateStandardHandles, duplicateInput, bridge.start()
// -- and then reads the handle handles.input ends up holding exactly as the
// account process would: through ReadFile on the inherited value, not
// through anything internal to this package.
//
// The optional mode selects what the child measures. It arrives either
// through TestMain's dispatch or, when the parent appended it to the child's
// command line, read here from this process's own arguments -- TestMain
// passes only the result file through, and the extra word costs that
// dispatcher nothing. Mode "stand-down" asks the question --own-console
// raises: with EnvOwnConsole set, duplicateInput must build no bridge even
// though stdin is a console, because the stub is about to hand the program a
// console of its own and nothing will read the bridge pipe anymore.
func stdinBridgeProbe(resultFile string, mode ...string) int {
	if len(mode) == 0 && len(os.Args) > 3 {
		mode = os.Args[3:4]
	}
	standDown := len(mode) > 0 && mode[0] == "stand-down"
	report := func(ok bool, msg string) int {
		prefix := "error: "
		if ok {
			prefix = "ok: "
		}
		_ = os.WriteFile(resultFile, []byte(prefix+msg), 0o600)
		if ok {
			return 0
		}
		return 1
	}
	fixupStdinFromConin()
	if !console(os.Stdin) {
		var mode uint32
		modeErr := syscall.GetConsoleMode(syscall.Handle(os.Stdin.Fd()), &mode)
		return report(false, fmt.Sprintf("os.Stdin is not a console inside the pseudo-console child (fd=%v, GetConsoleMode err=%v)", os.Stdin.Fd(), modeErr))
	}

	if standDown {
		if os.Getenv(EnvOwnConsole) == "" {
			return report(false, EnvOwnConsole+" is not set inside the pseudo-console child, so duplicateInput had nothing to stand down for and the check would prove nothing")
		}
		handles, err := duplicateStandardHandles()
		if err != nil {
			return report(false, "duplicateStandardHandles: "+err.Error())
		}
		before := handles.input
		bridge, err := duplicateInput(&handles)
		if err != nil {
			handles.close()
			return report(false, "duplicateInput: "+err.Error())
		}
		if bridge != nil {
			bridge.close()
			handles.close()
			return report(false, "duplicateInput built a bridge although "+EnvOwnConsole+" is set and the stub is about to hand the program a console of its own")
		}
		if handles.input != before {
			handles.close()
			return report(false, "duplicateInput replaced handles.input although it stood down")
		}
		handles.close()
		return report(true, "duplicateInput stood down for the stub's own console")
	}

	handles, err := duplicateStandardHandles()
	if err != nil {
		return report(false, "duplicateStandardHandles: "+err.Error())
	}
	bridge, err := duplicateInput(&handles)
	if err != nil {
		syscall.CloseHandle(handles.output)
		syscall.CloseHandle(handles.errout)
		return report(false, "duplicateInput: "+err.Error())
	}
	if bridge == nil {
		syscall.CloseHandle(handles.input)
		syscall.CloseHandle(handles.output)
		syscall.CloseHandle(handles.errout)
		return report(false, "duplicateInput built no bridge for a real console stdin")
	}
	bridge.start()

	// handles.input is now the exact handle value runAsAccount would place
	// in STARTUPINFO.StdInput for the account process; reading it directly,
	// through ReadFile via os.File, stands in for "the account process reads
	// its inherited stdin".
	reader := os.NewFile(uintptr(handles.input), "stdin-bridge-child")
	var line []byte
	buf := make([]byte, 64)
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(string(line), "\n") {
		if time.Now().After(deadline) {
			reader.Close()
			syscall.CloseHandle(handles.output)
			syscall.CloseHandle(handles.errout)
			return report(false, "timed out reading the bridged stdin, got so far: "+string(line))
		}
		n, readErr := reader.Read(buf)
		line = append(line, buf[:n]...)
		if readErr != nil {
			break
		}
	}
	reader.Close()
	syscall.CloseHandle(handles.output)
	syscall.CloseHandle(handles.errout)
	return report(true, strings.TrimSpace(string(line)))
}

// probeInsideAPseudoConsole starts a fresh child of this test binary
// attached to a Windows pseudo console, waits for it to end, and returns the
// report the child wrote to its result file and the exit code it ended on.
// mode, when not empty, is appended to the child's command line for
// stdinBridgeProbe to read. The child inherits this process's environment --
// CreateProcessW runs here with lpEnvironment = NULL -- so a caller that
// wants the child to see a variable sets it before calling; t.Setenv, which
// puts it back when the test ends, is the shape for that.
//
// The pty's two directions: what a person would type goes into
// ptyInWrite, ConPTY hands it to the child's console input buffer
// through ptyInRead; what the child's console prints comes out of
// ptyOutWrite into ptyOutRead. ptyOutRead is never read here -- draining
// it is not what these tests measure -- but it has to exist and stay
// open, or a child that writes anything to its own console output would
// block on a full pipe for a reason unrelated to what is being tested.
// The line is typed in every mode: the stand-down probe never reads it,
// and bytes nobody reads are simply drained when both ends close.
func probeInsideAPseudoConsole(t *testing.T, mode string) (string, uint32) {
	t.Helper()
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	resultFile := filepath.Join(t.TempDir(), "result.txt")

	ptyInRead, ptyInWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ptyInWrite.Close()
	ptyOutRead, ptyOutWrite, err := os.Pipe()
	if err != nil {
		ptyInRead.Close()
		t.Fatal(err)
	}
	defer ptyOutRead.Close()

	var hpc syscall.Handle
	// COORD{X: 80, Y: 25} packed into the single register the x64 calling
	// convention uses for a struct this size: X in the low 16 bits, Y in the
	// next 16, the same layout golang.org/x/sys/windows.CreatePseudoConsole
	// gets from *(*uint32)(unsafe.Pointer(&Coord{X, Y})).
	const width, height = 80, 25
	size := uintptr(uint32(uint16(width)) | uint32(uint16(height))<<16)
	r, _, callErr := procCreatePseudoConsole.Call(size, ptyInRead.Fd(), ptyOutWrite.Fd(), 0, uintptr(unsafe.Pointer(&hpc)))
	// CreatePseudoConsole duplicates what it needs from these; this
	// process's own copies are surplus the moment the call returns --
	// keeping them open would be exactly the ambient-inheritance hygiene
	// gap P2-1 was about, just on the test's own handles instead of
	// production's.
	ptyInRead.Close()
	ptyOutWrite.Close()
	if r != 0 {
		t.Fatalf("CreatePseudoConsole: hresult 0x%x (%v)", r, callErr)
	}
	defer procClosePseudoConsole.Call(uintptr(hpc))

	// startupInfoForPseudoConsole is the production builder; exercising it
	// here stands in for the hand-rolled attribute-list sequence this test
	// used to carry itself.
	startup, freeAttr, err := startupInfoForPseudoConsole(hpc)
	if err != nil {
		t.Fatal(err)
	}
	defer freeAttr()

	var created syscall.ProcessInformation
	commandLine := syscall.EscapeArg(exe) + " " + stdinBridgeProbeFlag + " " + syscall.EscapeArg(resultFile)
	if mode != "" {
		commandLine += " " + syscall.EscapeArg(mode)
	}
	line, err := syscall.UTF16PtrFromString(commandLine)
	if err != nil {
		t.Fatal(err)
	}
	// bInheritHandles is deliberately false: with the pseudo-console
	// attribute set, the child's standard handles come from the console
	// subsystem attachment, not from inherited STARTUPINFO handles or
	// ambient inheritance -- the same shape CreatePseudoConsoleSample in
	// Microsoft's own docs uses.
	const inheritHandles = 0
	const flags = extendedStartupInfoPresent
	r, _, callErr = procCreateProcessForPty.Call(
		0, uintptr(unsafe.Pointer(line)), 0, 0, inheritHandles, flags, 0, 0,
		uintptr(unsafe.Pointer(&startup.StartupInfo)), uintptr(unsafe.Pointer(&created)))
	runtime.KeepAlive(line)
	runtime.KeepAlive(startup)
	if r == 0 {
		t.Fatalf("CreateProcessW: %v", callErr)
	}
	defer syscall.CloseHandle(created.Thread)
	defer syscall.CloseHandle(created.Process)

	// What a person would type into the prompt.
	if _, err := ptyInWrite.WriteString("from-a-real-console\r\n"); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, waitErr := syscall.WaitForSingleObject(created.Process, syscall.INFINITE)
		done <- waitErr
	}()
	select {
	case waitErr := <-done:
		if waitErr != nil {
			t.Fatal(waitErr)
		}
	case <-time.After(30 * time.Second):
		procTerminateProcess.Call(uintptr(created.Process), 1)
		t.Fatal("the pseudo-console-attached probe did not finish in time")
	}

	var code uint32
	procGetExitCode.Call(uintptr(created.Process), uintptr(unsafe.Pointer(&code)))

	raw, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatalf("the probe wrote no result (exit code %d): %v", code, err)
	}
	return string(raw), code
}

// TestStdinBridgeCarriesRealConsoleInput is the surrogate for a human typing
// into an interactive cmd.exe prompt: a Windows pseudo console stands in for
// the console, a re-exec of this same test binary stands in for the account
// process, and duplicateInput/inputBridge.start run exactly as they would
// inside runAsAccount. What this measures: console(os.Stdin) recognizes the
// pseudo console's device side as a real console, duplicateInput builds a
// bridge for it instead of leaving the raw handle alone, and a byte string
// written into the pseudo console's input side arrives, through the bridge,
// at the handle value the account process would have inherited.
//
// What this does not measure: the account crossing itself, i.e. that
// CreateProcessWithLogonW's own inheritance still hands the account exactly
// that handle. That needs a real second account and administrator rights;
// TestTheStreamsComeBackFromInsideTheSandbox in streams_test.go covers the
// crossing, but always with os.Stdin already redirected to a pipe, never a
// real console (see internal/e2e/account_test.go's realBox.streams) -- so
// between the two, one test covers "is it a bridge at all" against a real
// console and the other covers "does the crossing preserve it" against a
// pipe, and nothing in this repository covers both properties on the same
// run, because nothing can build a real console and a second real account in
// the same test without asking a human to type into a terminal.
func TestStdinBridgeCarriesRealConsoleInput(t *testing.T) {
	report, code := probeInsideAPseudoConsole(t, "")
	if !strings.HasPrefix(report, "ok:") {
		t.Fatalf("probe reported %q (exit code %d)", report, code)
	}
	if !strings.Contains(report, "from-a-real-console") {
		t.Errorf("probe read %q, want it to contain what was typed into the pseudo console", report)
	}
}

// TestDuplicateInputStandsDownForTheStubsOwnConsole holds that the
// stand-down duplicateInput does under EnvOwnConsole is not keyed on stdin
// being redirected: it fires for a real console stdin too, which is the
// shape a run has when wuserbox was started from an interactive prompt --
// the one shape every other test in this file reaches only as a pipe, and
// the one where a bridge left running would carry the caller's keystrokes
// into a pipe nobody reads anymore. The same pseudo-console surrogate stands
// in for the console, and this time the child inherits EnvOwnConsole, set by
// the parent before the spawn and put back when the test ends, the way a run
// sets it.
//
// What this does not measure: the account crossing, exactly as in
// TestStdinBridgeCarriesRealConsoleInput above, and the window itself -- that
// AllocConsole makes a console a terminal program will actually accept.
// Allocating one inside this package's tests would put a window on the
// screen of every test run, which the createNoWindow comment in
// internal/win/proc/job.go records the cost of; the open-and-repoint half
// without the allocation is measured by internal/sandbox/exec's console
// test, and the whole chain, allocation and account crossing both, by
// internal/e2e's own-console test.
func TestDuplicateInputStandsDownForTheStubsOwnConsole(t *testing.T) {
	t.Setenv(EnvOwnConsole, "1")
	report, code := probeInsideAPseudoConsole(t, "stand-down")
	// The exact message, not just an ok prefix: the child that ignored its
	// mode and ran the bridge probe would also report ok, carrying the
	// typed line back instead of the stand-down answer.
	if report != "ok: duplicateInput stood down for the stub's own console" {
		t.Fatalf("probe reported %q (exit code %d), want the stand-down answer", report, code)
	}
}
