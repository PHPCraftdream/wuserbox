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
	"encoding/binary"
	"fmt"
	"io"
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
	procResizePseudoConsole  = w32.Kernel32.NewProc("ResizePseudoConsole")
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

// fixupStdinFromConin compensates for this file's probe launch shape, not
// production's any more: the re-exec here goes through plain CreateProcessW
// with no standard-handle treatment, so the child's os.Stdin -- captured
// from GetStdHandle at runtime init -- holds values that name nothing, even
// though the process is genuinely attached to its pseudo console. The
// production launch no longer has this gap: RunWithConsole starts its
// children with NULL standard handles and the console attachment hands them
// the console's own, which is
// TestRunWithConsoleGivesTheChildAWorkingGetStdHandle in relay_test.go's
// measurement. This fallback stays because the probe still needs it, and
// because the CONIN$-by-name path it takes is what a program left with
// unusable standard handles falls back to -- the same shape the C runtime's
// own startup and exec's openConsoleStreams follow.
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

// fixupStdoutFromConout is fixupStdinFromConin's counterpart for the output
// side, and compensates for the same gap fixupStdinFromConin does -- see its
// own comment for where that gap actually comes from.
// Rather than repoint
// os.Stdout, this returns the console file itself for the one caller that
// wants to measure a viewport: production measures os.Stdout, which a real
// operator console populates. nil when even CONOUT$ will not answer, which
// means there is no console to measure and the caller says so.
func fixupStdoutFromConout() *os.File {
	name, err := syscall.UTF16PtrFromString("CONOUT$")
	if err != nil {
		return nil
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil
	}
	candidate := os.NewFile(uintptr(handle), "CONOUT$")
	if !console(candidate) {
		_ = candidate.Close()
		return nil
	}
	return candidate
}

// readResizeMessage reads exactly one resize message -- ResizeMessageLen
// bytes, the length both ends of the relay's resize pipe share -- and
// unpacks it the way encodeResize packed it: columns first, then rows. A
// read deadline the caller set on r is what bounds the wait; this measures
// nothing on its own.
func readResizeMessage(r io.Reader) (cols, rows uint16, err error) {
	var message [ResizeMessageLen]byte
	if _, err = io.ReadFull(r, message[:]); err != nil {
		return 0, 0, err
	}
	return binary.LittleEndian.Uint16(message[0:]),
		binary.LittleEndian.Uint16(message[2:]), nil
}

// readResizeWithin races one resize message against within. It has to be a
// race: an os.Pipe end on Windows is a synchronous CreatePipe handle, where
// SetReadDeadline answers ErrNoDeadline and a read with nothing to read
// blocks for good -- measured while building the watcher test, which hung
// on exactly that. The loser leaves its read blocked in the kernel, which
// is harmless here and once per test, and never comes up in production:
// every production reader of these pipes is entitled to wait for as long
// as the run lasts, because the other end closing is the only thing that
// is ever allowed to end one.
func readResizeWithin(r *os.File, within time.Duration) (cols, rows uint16, ok bool) {
	type sized struct {
		cols uint16
		rows uint16
	}
	done := make(chan sized, 1)
	go func() {
		c, ro, err := readResizeMessage(r)
		if err != nil {
			return
		}
		done <- sized{c, ro}
	}()
	select {
	case s := <-done:
		return s.cols, s.rows, true
	case <-time.After(within):
		return 0, 0, false
	}
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
	relayStandDown := len(mode) > 0 && mode[0] == "relay-stand-down"
	relayInputMode := len(mode) > 0 && mode[0] == "relay-input"
	relayCtrlCMode := len(mode) > 0 && mode[0] == "relay-ctrlc"
	relayKillRestoreMode := len(mode) > 0 && mode[0] == "relay-kill-restore"
	relayResizeDetectMode := len(mode) > 0 && mode[0] == "relay-resize-detect"
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

	if relayStandDown {
		if os.Getenv(EnvConsoleRelay) == "" {
			return report(false, EnvConsoleRelay+" is not set inside the pseudo-console child, so duplicateInput had nothing to stand down for and the check would prove nothing")
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
			return report(false, "duplicateInput built a bridge although "+EnvConsoleRelay+" is set and the relay owns the input side")
		}
		if handles.input != before {
			handles.close()
			return report(false, "duplicateInput replaced handles.input although it stood down")
		}
		handles.close()
		return report(true, "duplicateInput stood down for the console relay")
	}

	if relayInputMode {
		if os.Getenv(EnvConsoleRelay) == "" {
			return report(false, EnvConsoleRelay+" is not set inside the pseudo-console child, so the relay's own input pipe had nothing to carry and the check would prove nothing")
		}
		handles, err := duplicateStandardHandles()
		if err != nil {
			return report(false, "duplicateStandardHandles: "+err.Error())
		}
		bridge, err := duplicateInput(&handles)
		if err != nil {
			handles.close()
			return report(false, "duplicateInput: "+err.Error())
		}
		if bridge != nil {
			bridge.close()
			handles.close()
			return report(false, "duplicateInput built the ordinary bridge although "+EnvConsoleRelay+" is set and the relay owns the input side")
		}
		relay, err := relayInput(&handles)
		if err != nil {
			handles.close()
			return report(false, "relayInput: "+err.Error())
		}
		if relay == nil {
			syscall.CloseHandle(handles.input)
			syscall.CloseHandle(handles.output)
			syscall.CloseHandle(handles.errout)
			return report(false, "relayInput built no pipe for a real console stdin")
		}
		relay.start()
		// handles.input is now the pipe relayInput built, the exact value
		// runAsAccount would place in STARTUPINFO.StdInput for the account
		// process; reading it here stands in for the stub reading its
		// inherited stdin, the pump on the far side carrying it the last
		// hop into the pseudo console's own input.
		reader := os.NewFile(uintptr(handles.input), "relay-input-child")
		var line []byte
		buf := make([]byte, 64)
		deadline := time.Now().Add(20 * time.Second)
		for !strings.Contains(string(line), "\n") {
			if time.Now().After(deadline) {
				reader.Close()
				syscall.CloseHandle(handles.output)
				syscall.CloseHandle(handles.errout)
				return report(false, "timed out reading the relay's input pipe, got so far: "+string(line))
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

	if relayCtrlCMode {
		if os.Getenv(EnvConsoleRelay) == "" {
			return report(false, EnvConsoleRelay+" is not set inside the pseudo-console child, so the relay's own input pipe had nothing to carry and the check would prove nothing")
		}
		// The production operator-side pairing, in the order a run does it:
		// the mode change first, the stand-down, relayInput's pipe, and the
		// interrupt forwarder. The pty's console answers Get/SetConsoleMode
		// the same as a real one, which relayConsoleModes succeeding here is
		// the measurement of.
		restore, err := relayConsoleModes()
		if err != nil {
			return report(false, "relayConsoleModes: "+err.Error())
		}
		defer restore()
		handles, err := duplicateStandardHandles()
		if err != nil {
			return report(false, "duplicateStandardHandles: "+err.Error())
		}
		bridge, err := duplicateInput(&handles)
		if err != nil {
			handles.close()
			return report(false, "duplicateInput: "+err.Error())
		}
		if bridge != nil {
			bridge.close()
			handles.close()
			return report(false, "duplicateInput built the ordinary bridge although "+EnvConsoleRelay+" is set and the relay owns the input side")
		}
		relay, err := relayInput(&handles)
		if err != nil {
			handles.close()
			return report(false, "relayInput: "+err.Error())
		}
		if relay == nil {
			syscall.CloseHandle(handles.input)
			syscall.CloseHandle(handles.output)
			syscall.CloseHandle(handles.errout)
			return report(false, "relayInput built no pipe for a real console stdin")
		}
		relay.start()
		relayWatchInterrupts(relay.write)
		// handles.input is the pipe relayInput built, read here exactly as
		// relay-input reads it; what is different is the source. Group 0 is
		// every process attached to the caller's console, and this probe is
		// the pty console's only attached process -- the parent holds the
		// pty's pipe ends, not the console. CTRL_BREAK is the exercisable
		// path because interrupt_test.go measured that
		// CREATE_NEW_PROCESS_GROUP processes ignore CTRL_C_EVENT, and that
		// Go's runtime maps both events to the same os.Interrupt the
		// forwarder listens for; the probe has a console -- the pty's --
		// which is the condition that file's notes say a
		// GenerateConsoleCtrlEvent caller needs.
		if r, _, callErr := procGenerateCtrlEvent.Call(ctrlBreakEvent, 0); r == 0 {
			syscall.CloseHandle(handles.input)
			syscall.CloseHandle(handles.output)
			syscall.CloseHandle(handles.errout)
			return report(false, "GenerateConsoleCtrlEvent: "+callErr.Error())
		}
		reader := os.NewFile(uintptr(handles.input), "relay-ctrlc-child")
		var all []byte
		buf := make([]byte, 64)
		deadline := time.Now().Add(20 * time.Second)
		found := false
		for !found {
			if time.Now().After(deadline) {
				reader.Close()
				syscall.CloseHandle(handles.output)
				syscall.CloseHandle(handles.errout)
				return report(false, fmt.Sprintf("timed out waiting for the forwarded Ctrl-C byte, got so far: %x", all))
			}
			n, readErr := reader.Read(buf)
			all = append(all, buf[:n]...)
			for _, b := range buf[:n] {
				if b == ctrlCByte {
					found = true
					break
				}
			}
			if readErr != nil {
				break
			}
		}
		reader.Close()
		syscall.CloseHandle(handles.output)
		syscall.CloseHandle(handles.errout)
		if !found {
			return report(false, fmt.Sprintf("the relay's input pipe ended without a forwarded Ctrl-C byte, got: %x", all))
		}
		return report(true, fmt.Sprintf("the forwarded 0x03 arrived among %d byte(s): %x", len(all), all))
	}

	if relayKillRestoreMode {
		if os.Getenv(EnvConsoleRelay) == "" {
			return report(false, EnvConsoleRelay+" is not set inside the pseudo-console child, so the relay's modes had nothing to answer for and the check would prove nothing")
		}
		handle := syscall.Handle(os.Stdin.Fd())
		var original uint32
		if err := syscall.GetConsoleMode(handle, &original); err != nil {
			return report(false, "reading the original console mode: "+err.Error())
		}
		restore, err := relayConsoleModes()
		if err != nil {
			return report(false, "relayConsoleModes: "+err.Error())
		}
		var relayed uint32
		if err := syscall.GetConsoleMode(handle, &relayed); err != nil {
			restore()
			return report(false, "reading the relayed console mode back: "+err.Error())
		}
		if relayed == original {
			restore()
			return report(false, fmt.Sprintf("the relay shape left the mode at %d, unchanged, so there is nothing for a restore to put back", original))
		}
		// The close-class event, answered the way the registered handler
		// would answer it: the exact original mode word must come back.
		relayCtrlRestoreHandler(ctrlCloseEvent, restore)
		var afterClose uint32
		if err := syscall.GetConsoleMode(handle, &afterClose); err != nil {
			return report(false, "reading the mode back after the close-class restore: "+err.Error())
		}
		if afterClose != original {
			return report(false, fmt.Sprintf("the close event left %d, want the original %d back", afterClose, original))
		}
		// In the relay shape again, then the two interrupt events: the
		// handler must not act on them -- acting would fight the forwarding
		// machinery -- so the mode must still read as the relay shape.
		restore2, err := relayConsoleModes()
		if err != nil {
			return report(false, "relayConsoleModes: "+err.Error())
		}
		defer restore2()
		relayCtrlRestoreHandler(ctrlCEvent, restore2)
		relayCtrlRestoreHandler(ctrlBreakEvent, restore2)
		var afterInterrupts uint32
		if err := syscall.GetConsoleMode(handle, &afterInterrupts); err != nil {
			return report(false, "reading the mode back after the interrupt events: "+err.Error())
		}
		if afterInterrupts != relayed {
			return report(false, fmt.Sprintf("the interrupt events left %d, want the relay shape %d untouched", afterInterrupts, relayed))
		}
		return report(true, fmt.Sprintf("the close event put %d back over %d, and both interrupt events left the relay shape %d alone", original, relayed, afterInterrupts))
	}

	if relayResizeDetectMode {
		// This mode measures the resize watcher alone: no EnvConsoleRelay
		// involvement, no relayConsoleModes, no relayInput.
		conout := fixupStdoutFromConout()
		if conout == nil {
			return report(false, "CONOUT$ inside the pseudo-console child did not answer GetConsoleMode, so the resize watcher has no console to measure")
		}
		defer conout.Close()
		resizeRead, resizeWrite, err := os.Pipe()
		if err != nil {
			conout.Close()
			return report(false, "os.Pipe for the resize messages: "+err.Error())
		}
		defer resizeRead.Close()
		defer resizeWrite.Close()
		startRelayResize(conout, resizeWrite)
		startCols, startRows, ok := readResizeWithin(resizeRead, 20*time.Second)
		if !ok {
			return report(false, "the resize watcher's first message never arrived within 20s")
		}
		if startCols != 80 || startRows != 25 {
			return report(false, fmt.Sprintf("the resize watcher's first message was %dx%d, want the pseudo console's birth size 80x25", startCols, startRows))
		}
		// Written only after the first measurement, never before, so the
		// parent's resize cannot race the baseline.
		if err := os.WriteFile(resultFile+".ready", []byte("ready"), 0o600); err != nil {
			return report(false, "writing the baseline ready marker: "+err.Error())
		}
		for {
			cols, rows, ok := readResizeWithin(resizeRead, 20*time.Second)
			if !ok {
				return report(false, fmt.Sprintf("timed out waiting for a size different from %dx%d", startCols, startRows))
			}
			if cols != startCols || rows != startRows {
				return report(true, fmt.Sprintf("measured %dx%d at start and %dx%d after the resize", startCols, startRows, cols, rows))
			}
		}
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
//
// afterReady, when given, runs right after the typed line is written and
// before the child is waited for, called with the pty handle and the
// result file path. It is how a parent acts on the pty mid-flight: the
// resize test needs the child alive and past its baseline measurement
// before the console changes, and this is the point between those.
func probeInsideAPseudoConsole(t *testing.T, mode string, afterReady ...func(hpc syscall.Handle, resultFile string)) (string, uint32) {
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

	if len(afterReady) > 0 {
		afterReady[0](hpc, resultFile)
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

// TestDuplicateInputStandsDownForTheConsoleRelay is
// TestDuplicateInputStandsDownForTheStubsOwnConsole's counterpart for the
// relay: with EnvConsoleRelay set, the input side of the crossing belongs
// to relayInput, and the ordinary bridge standing down is what keeps one
// console from ever being read by two bridges. The same pseudo-console
// surrogate supplies the console, and the child inherits the variable, the
// way a run sets it.
//
// What this does not measure: the account crossing, exactly as in
// TestStdinBridgeCarriesRealConsoleInput above.
func TestDuplicateInputStandsDownForTheConsoleRelay(t *testing.T) {
	t.Setenv(EnvConsoleRelay, "1")
	report, code := probeInsideAPseudoConsole(t, "relay-stand-down")
	// The exact message, not just an ok prefix: a child that ignored its
	// mode and ran the bridge probe would also report ok, carrying the
	// typed line back instead of the stand-down answer.
	if report != "ok: duplicateInput stood down for the console relay" {
		t.Fatalf("probe reported %q (exit code %d), want the stand-down answer", report, code)
	}
}

// TestTheRelayInputBridgeCarriesRealConsoleInput measures the input side
// of the console relay against a real console: duplicateInput stands down,
// relayInput builds the relay's own pipe for that same console, and a line
// typed into the console arrives at the handle value runAsAccount would
// hand the stub as its stdin.
//
// What this does not measure: the stub-side pump, which is
// internal/sandbox/exec's and is covered there, and the account crossing,
// which needs a real second account and a typed console on the far side at
// once -- the same gap every test in this file records.
func TestTheRelayInputBridgeCarriesRealConsoleInput(t *testing.T) {
	t.Setenv(EnvConsoleRelay, "1")
	report, code := probeInsideAPseudoConsole(t, "relay-input")
	if !strings.HasPrefix(report, "ok:") {
		t.Fatalf("probe reported %q (exit code %d)", report, code)
	}
	if !strings.Contains(report, "from-a-real-console") {
		t.Errorf("probe read %q, want it to contain what was typed into the pseudo console", report)
	}
}
