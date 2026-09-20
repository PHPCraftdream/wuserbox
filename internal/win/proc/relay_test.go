package proc

// The relay's interrupt and resize forwarding, measured where a test can
// reach them: a forwarded Ctrl-C arriving as the keyboard byte, the resize
// watcher against a real pty resize, and the wire format and loop behavior
// both ends of the resize pipe share. The pseudo console is the surrogate
// stdin_bridge_test.go builds and the relay probes there run in; ResizePseudoConsole
// is what a real terminal calls when the operator drags its edge, so what the
// resize test measures is the same viewport a human's resize would change.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestTheRelayCarriesAForwardedCtrlCAsTheKeyboardByte proves the piece of
// the relay a keyboard cannot do for itself: a console interrupt raised the
// way the console layer raises them -- GenerateConsoleCtrlEvent, CTRL_BREAK
// per the lessons interrupt_test.go recorded -- is forwarded by the
// production pairing (relayConsoleModes, duplicateInput standing down,
// relayInput's pipe, relay.start, relayWatchInterrupts) into the relay's
// input pipe as the byte a keyboard would have sent.
//
// What this does not measure: the account crossing, as every test in
// stdin_bridge_test.go records, and that a real run's waitOrStop still
// counts the same event -- that listener's behavior is measured by
// interrupt_test.go and is unchanged by construction, Notify listeners each
// getting a copy.
func TestTheRelayCarriesAForwardedCtrlCAsTheKeyboardByte(t *testing.T) {
	t.Setenv(EnvConsoleRelay, "1")
	report, code := probeInsideAPseudoConsole(t, "relay-ctrlc")
	if !strings.HasPrefix(report, "ok:") {
		t.Fatalf("probe reported %q (exit code %d)", report, code)
	}
	if !strings.Contains(report, "0x03") {
		t.Errorf("probe read %q, want it to contain the forwarded Ctrl-C byte", report)
	}
}

// ctrlCEvent is CTRL_C_EVENT, event 0; its sibling ctrlBreakEvent lives in
// driver_test.go, where the tests that generate the events run.
const ctrlCEvent = 0

// TestTheKillRestoreHandlerAnswersOnlyTheEventsThatEndTheProcess pins the
// whole decision relayCtrlRestoreHandler makes, with no console and no
// registered handler in sight: the three close-class events -- close,
// logoff, shutdown -- are each answered FALSE with the restore called
// exactly once, and the two interrupt events -- Ctrl-C, Ctrl-Break -- are
// answered FALSE with the restore never called, which is what leaves
// waitOrStop's first-press policy and the forwarding machinery alone.
//
// What this does not measure: that Windows calls the handler at all on a
// console close, which is the documented contract reasoned over in
// startRelayKillRestore's comment, and the restore's effect on real mode
// words, which the probe test below measures on a real one.
func TestTheKillRestoreHandlerAnswersOnlyTheEventsThatEndTheProcess(t *testing.T) {
	for _, tc := range []struct {
		name      string
		event     uint32
		wantCalls int
	}{
		{"the console closing", ctrlCloseEvent, 1},
		{"logoff", ctrlLogoffEvent, 1},
		{"shutdown", ctrlShutdownEvent, 1},
		{"Ctrl-C", ctrlCEvent, 0},
		{"Ctrl-Break", ctrlBreakEvent, 0},
	} {
		calls := 0
		got := relayCtrlRestoreHandler(tc.event, func() { calls++ })
		if got != 0 {
			t.Errorf("%s: handler returned %d, want 0 (FALSE) -- a TRUE return would swallow the event", tc.name, got)
		}
		if calls != tc.wantCalls {
			t.Errorf("%s: restore called %d times, want %d", tc.name, calls, tc.wantCalls)
		}
	}
}

// TestTheRelayRegistersItsKillRestoreHandlerAndTakesItBack proves, live in
// this process, that syscall.NewCallback accepts the closure
// startRelayKillRestore builds and SetConsoleCtrlHandler accepts the
// resulting pointer, and that the removal comes back without error -- the
// three calls a relay run makes around its own registration, exercised
// without a console or a kill anywhere near.
//
// What this does not measure: the handler firing, which needs Windows to
// deliver a close-class event and nothing in this process can synthesize
// one -- see TestTheKillRestoreHandlerPutsARealConsoleBack for what a
// pseudo-console child can still reach.
func TestTheRelayRegistersItsKillRestoreHandlerAndTakesItBack(t *testing.T) {
	stop, err := startRelayKillRestore(func() {})
	if err != nil {
		t.Fatalf("registering the console restore handler: %v", err)
	}
	stop()
}

// TestTheKillRestoreHandlerPutsARealConsoleBack runs the selection the unit
// test above pins against a real console: inside the pseudo-console child,
// whose os.Stdin is a pty console for the same reason an interactive
// prompt's is, the input mode is read, the relay shape is taken on and
// confirmed to have changed it, the close-class event is handed to
// relayCtrlRestoreHandler and the original mode word must come back
// exactly, and both interrupt events must then leave a second relay shape
// untouched.
//
// The honest limits: GenerateConsoleCtrlEvent can only synthesize
// CTRL_C_EVENT and CTRL_BREAK_EVENT, so a real CTRL_CLOSE_EVENT delivery
// cannot be produced in-process -- what is measured live is the selection,
// the FALSE return, the exact restore values on a real console, and that
// SetConsoleCtrlHandler accepts the handler; that Windows actually calls
// the handler on a console close is the documented contract, reasoned not
// measured here. The mode words are machine-specific, so only the ok
// prefix and the "left the relay shape" phrase are pinned, the latter
// being what catches a probe that ignored its mode and reported
// something else.
func TestTheKillRestoreHandlerPutsARealConsoleBack(t *testing.T) {
	t.Setenv(EnvConsoleRelay, "1")
	report, code := probeInsideAPseudoConsole(t, "relay-kill-restore")
	if !strings.HasPrefix(report, "ok:") {
		t.Fatalf("probe reported %q (exit code %d)", report, code)
	}
	if !strings.Contains(report, "left the relay shape") {
		t.Errorf("probe reported %q, want it to contain the interrupt-events answer", report)
	}
}

// TestTheRelayResizeWatcherMeasuresAPtyResize is the "synthetic resize
// without a literal screen" the feature needs: ResizePseudoConsole is what
// a real terminal calls to change its size, so resizing the pty through it
// changes the same viewport the watcher's consoleSize measures -- and
// nothing here needs a window on the desktop.
func TestTheRelayResizeWatcherMeasuresAPtyResize(t *testing.T) {
	afterReady := func(hpc syscall.Handle, resultFile string) {
		// The child writes this marker only after its baseline
		// measurement, so the resize below cannot race it.
		if !waitForFile(resultFile+".ready", 20*time.Second) {
			t.Fatalf("the probe never measured its baseline (%s.ready never appeared)", resultFile)
		}
		// COORD{X: 101, Y: 37} packed into the single register the x64
		// calling convention uses for a struct this size, exactly the way
		// probeInsideAPseudoConsole packs the birth size 80x25.
		const newWidth, newHeight = 101, 37
		size := uintptr(uint32(uint16(newWidth)) | uint32(uint16(newHeight))<<16)
		r, _, callErr := procResizePseudoConsole.Call(uintptr(hpc), size)
		if r != 0 {
			t.Fatalf("ResizePseudoConsole: hresult 0x%x (%v)", r, callErr)
		}
	}
	report, code := probeInsideAPseudoConsole(t, "relay-resize-detect", afterReady)
	// The exact message, not just an ok prefix: the stand-down tests'
	// pattern -- a child that ignored its mode could otherwise report ok.
	if report != "ok: measured 80x25 at start and 101x37 after the resize" {
		t.Fatalf("probe reported %q (exit code %d), want the exact resize measurement", report, code)
	}
}

// TestAResizeMessageIsTwoLittleEndianUint16s is the wire format both ends
// of the resize pipe share.
func TestAResizeMessageIsTwoLittleEndianUint16s(t *testing.T) {
	got := encodeResize(101, 37)
	want := []byte{101, 0, 37, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("encodeResize(101, 37) = %v, want %v", got, want)
	}
	if ResizeMessageLen != len(want) {
		t.Fatalf("ResizeMessageLen = %d, want %d", ResizeMessageLen, len(want))
	}
}

// TestTheResizeWatcherPushesTheInitialSizeAndThenOnlyChanges pins the two
// loop behaviors a relay run depends on: the first message is written
// before the first wait -- the initial push is why a run begun in a 120x40
// terminal does not live at the pseudo console's birth size -- and
// same-size polls write nothing until the re-assert falls due, which is
// what keeps the pipe quiet.
func TestTheResizeWatcherPushesTheInitialSizeAndThenOnlyChanges(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()

	measurements := [][2]uint16{{80, 25}, {80, 25}, {101, 37}}
	next := 0
	var retire atomic.Bool
	size := func() (uint16, uint16, bool) {
		if retire.Load() {
			// A size the loop has never seen, so its last tick
			// really has something to write.
			return 140, 50, true
		}
		if next < len(measurements) {
			m := measurements[next]
			next++
			return m[0], m[1], true
		}
		// After exhaustion: unchanged, so nothing more is written.
		last := measurements[len(measurements)-1]
		return last[0], last[1], true
	}
	go relayResizeLoop(write, 5*time.Millisecond, size)

	cols, rows, ok := readResizeWithin(read, 20*time.Second)
	if !ok {
		t.Fatalf("the initial push never arrived")
	}
	if cols != 80 || rows != 25 {
		t.Fatalf("first message was %dx%d, want the initial push 80x25", cols, rows)
	}
	cols, rows, ok = readResizeWithin(read, 20*time.Second)
	if !ok {
		t.Fatalf("the change never arrived")
	}
	if cols != 101 || rows != 37 {
		t.Fatalf("second message was %dx%d, want the change 101x37", cols, rows)
	}
	// The two same-size polls wrote nothing between the initial push and
	// the change, and nothing writes after the change either, so the
	// quietness read is raced against 300ms -- about sixty 5ms ticks --
	// because a SetReadDeadline on an os.Pipe end is a no-op on Windows
	// (measured; see readResizeWithin) -- and the window is deliberately
	// shorter than resizeReassertInterval, which is what keeps "quiet"
	// and "re-assert due" from colliding in the test.
	cols, rows, ok = readResizeWithin(read, 300*time.Millisecond)
	if ok {
		t.Fatalf("a third message %dx%d arrived; same-size polls must write nothing", cols, rows)
	}

	// The loop's only exit is a failed write, so retiring it means closing
	// the pipe under it and making the fake report a size it must forward;
	// the third read's loser is left blocked in the kernel on purpose and
	// retires with the process.
	_ = write.Close()
	retire.Store(true)
	time.Sleep(50 * time.Millisecond)
}

// TestTheResizeWatcherReassertsItsSizeBeforeTheReassertIntervalElapses
// pins the re-assert beat the loop gained alongside its change writes:
// with nothing changing, the size it last reported is re-written once per
// resizeReassertInterval anyway, so a shape whose first message was
// consumed before the program attached comes back on this beat instead of
// never.
func TestTheResizeWatcherReassertsItsSizeBeforeTheReassertIntervalElapses(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()

	var retire atomic.Bool
	size := func() (uint16, uint16, bool) {
		if retire.Load() {
			// A size the loop has never seen, so its last tick
			// really has something to write.
			return 140, 50, true
		}
		return 101, 37, true
	}
	go relayResizeLoop(write, 5*time.Millisecond, size)

	cols, rows, ok := readResizeWithin(read, 20*time.Second)
	if !ok {
		t.Fatalf("the initial push never arrived")
	}
	if cols != 101 || rows != 37 {
		t.Fatalf("first message was %dx%d, want the initial push 101x37", cols, rows)
	}
	// The re-assert: one more write once resizeReassertInterval has
	// elapsed since the last one. This is the beat a dropped first shape
	// comes back on.
	cols, rows, ok = readResizeWithin(read, 3*time.Second)
	if !ok {
		t.Fatalf("the re-assert never arrived")
	}
	if cols != 101 || rows != 37 {
		t.Fatalf("second message was %dx%d, want the re-assert 101x37", cols, rows)
	}
	// And exactly one: with the last write one 5ms tick behind us, the
	// next beat is not due yet, so a quietness read raced over 300ms --
	// far inside resizeReassertInterval, and raced for the same no-op
	// SetReadDeadline reason the sibling test records -- must find
	// nothing.
	cols, rows, ok = readResizeWithin(read, 300*time.Millisecond)
	if ok {
		t.Fatalf("a third message %dx%d arrived; the next re-assert is not due yet", cols, rows)
	}

	// The loop's only exit is a failed write, so retiring it means closing
	// the pipe under it and making the fake report a size it must forward;
	// the third read's loser is left blocked in the kernel on purpose and
	// retires with the process.
	_ = write.Close()
	retire.Store(true)
	time.Sleep(50 * time.Millisecond)
}

// TestConsoleSizeAnswersOnARealConsole: go test without a console has
// nothing to measure, so this skips there and only asks for sane positive
// dimensions where there is one.
func TestConsoleSizeAnswersOnARealConsole(t *testing.T) {
	if !console(os.Stdout) {
		t.Skip("os.Stdout is not a console in this run, so there is no viewport to measure")
	}
	cols, rows, ok := consoleSize(os.Stdout)
	if !ok {
		t.Fatal("consoleSize did not answer on a console stdout")
	}
	if cols == 0 || rows == 0 {
		t.Fatalf("consoleSize measured %dx%d, want positive dimensions", cols, rows)
	}
}

// TestRunWithConsoleGivesTheChildAWorkingGetStdHandle is the regression
// test for a real bug that reached CI: a child started attached to a
// pseudo console through CreateProcessAsUserW held GetStdHandle values
// that answered nothing, even though the pseudo console attribute was
// present and CONIN$/CONOUT$ opened and answered GetConsoleMode correctly
// by name. A program that reads GetStdHandle directly rather than opening
// the console devices by name -- PowerShell's own
// [Console]::IsInputRedirected and IsOutputRedirected among them --
// reported itself redirected and never saw the relay at all, measured
// live on the account-crossing e2e suite in CI: docs/investigations
// records the pseudo console working end to end, but every measurement
// there fed a program that opened CONIN$/CONOUT$ itself, PowerShell's own
// redirection check never having been exercised until the
// account-crossing test finally ran with real administrator rights.
//
// The cause, and the fix this test holds in place: a child launched
// without STARTF_USESTDHANDLES inherits its parent's standard handle
// values, and values are all that cross -- with bInheritHandles false the
// handles behind them stay in the parent's table, so the child is left
// holding numbers that name nothing, and nothing in the console attach
// overwrites std handle values that are already set. RunWithConsole now
// starts the child with NULL standard handles -- STARTF_USESTDHANDLES,
// all three fields zero -- and a child attached to a console with no
// standard handles of its own is handed the attachment's own handles: the
// same launch measured here answers with FILE_TYPE_CHAR values whose
// GetConsoleMode modes are the relayed console's own. That the handing is
// the attachment's, not something about the values, is the contrast the
// launch-shape matrix was run for --
// docs/investigations/2026-09-20-same-window-console.md section 5, where a
// detached child gets nothing and a CREATE_NO_WINDOW child gets a
// different console's handles.
//
// CREATE_NO_WINDOW is not the fix, and was tried and measured wrong:
// adding it to RunWithConsole's flags does make this test pass, but it
// does so by silently detaching the child from the pseudo console named
// in the STARTUPINFOEX attribute onto a separate, hidden console of its
// own -- a real one, hence GetStdHandle answering correctly -- rather
// than fixing the attachment. That was caught by this package's sibling
// in internal/sandbox/exec: with the flag added,
// TestTheConsoleRelayCarriesTheChildsRenderedOutput's captured output
// went to empty (nothing crosses to a console the child was never
// actually attached to) and
// TestTheRelayPumpCarriesRenderedBytesOutAndKeystrokesIn hung outright.
// The real fix had to make GetStdHandle answer correctly *for the same
// console the pseudo console attribute names*, not hand the child a
// different one; the paragraph above is that shape, and this test is
// what keeps it.
//
// This runs same-account, no elevation and nothing account-crossing about
// it: the property under test -- whether GetStdHandle answers usably for a
// child attached to the given pseudo console -- does not depend on which
// token names the account, only on how that attachment is built, which is
// exactly what a same-account reproduction can isolate and iterate against
// far more cheaply than a CI round trip.
//
// The report crosses through a file PowerShell writes with Set-Content, not
// through the pseudo console's own rendered-output pipe: a first draft read
// the pipe instead and measured PowerShell's ordinary Write-Output not
// reaching it before the process exited and the console closed -- .NET's
// own buffered console writer, not GetStdHandle, and not what this test is
// about. Set-Content writes the file directly, independent of that
// buffering, and is the same shape the fix itself was confirmed with.
func TestRunWithConsoleGivesTheChildAWorkingGetStdHandle(t *testing.T) {
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inWrite.Close()
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var hpc syscall.Handle
	const width, height = 80, 25
	size := uintptr(uint32(uint16(width)) | uint32(uint16(height))<<16)
	r, _, callErr := procCreatePseudoConsole.Call(size, inRead.Fd(), outWrite.Fd(), 0, uintptr(unsafe.Pointer(&hpc)))
	inRead.Close()
	outWrite.Close()
	if r != 0 {
		t.Fatalf("CreatePseudoConsole: hresult 0x%x (%v)", r, callErr)
	}
	// Nothing reads this pipe -- the report crosses through a file instead,
	// for the reason above -- so it is drained only to keep conhost's own
	// writes from blocking on a full pipe, never inspected.
	go func() { _, _ = io.Copy(io.Discard, outRead) }()
	defer procClosePseudoConsole.Call(uintptr(hpc))
	defer outRead.Close()

	var own syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()

	resultFile := filepath.Join(t.TempDir(), "redirected.txt")
	commandLine := fmt.Sprintf(
		`powershell.exe -NoProfile -Command "'redirected=' + [Console]::IsInputRedirected + ',' + `+
			`[Console]::IsOutputRedirected | Set-Content -LiteralPath '%s'"`,
		resultFile)
	code, err := RunWithConsole(own, commandLine, t.TempDir(), hpc)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("the probe ended with exit code %d, want 0", code)
	}

	raw, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatalf("the probe wrote no result (exit code %d): %v", code, err)
	}
	report := strings.TrimSpace(string(raw))
	if report != "redirected=False,False" {
		t.Errorf("PowerShell reported %q, want \"redirected=False,False\"", report)
	}
}
