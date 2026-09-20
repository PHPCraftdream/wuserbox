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
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
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
