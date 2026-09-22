// Repointing the standard streams at a console the process already has.
//
// takeOwnConsole has two halves: AllocConsole makes the stub a console of
// its own, and openConsoleStreams opens CONIN$/CONOUT$ by name and points
// os.Stdin, os.Stdout and os.Stderr at it. The first half cannot be
// exercised inside a test run without putting a window on the screen of
// every test run -- AllocConsole makes a real one, and one per test is
// exactly what the createNoWindow comment in internal/win/proc/job.go
// records the cost of, windows appearing and stealing the keyboard from
// whoever is using the machine. So what is covered here is the second half,
// the open-and-repoint, which needs no allocation at all when the test
// process already has a console, as it does under `go test` from a terminal:
// the same two calls run, and the streams they install name a real console.
// The allocation half is measured end to end by internal/e2e's own-console
// test and by the live runs against a real sandbox, where the window on the
// screen is the product working rather than a test misbehaving.

package exec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procGetStdHandle         = w32.Kernel32.NewProc("GetStdHandle")
	procSetStdHandle         = w32.Kernel32.NewProc("SetStdHandle")
	procGetHandleInformation = w32.Kernel32.NewProc("GetHandleInformation")
)

// TestOpenConsoleStreamsRepointsTheStandardStreamsAtARealConsole covers the
// AllocConsole-free half of takeOwnConsole: openConsoleStreams opens the
// console devices and installs them as this process's standard streams,
// allocating nothing. Most harnesses run this binary without a console of
// its own, and there the open fails and the test skips -- the repointing has
// nothing real to be measured against, and standing a console up for it
// would put the window back on the screen.
func TestOpenConsoleStreamsRepointsTheStandardStreamsAtARealConsole(t *testing.T) {
	oldStdin, oldStdout, oldStderr := os.Stdin, os.Stdout, os.Stderr
	restore := func() { os.Stdin, os.Stdout, os.Stderr = oldStdin, oldStdout, oldStderr }
	err := openConsoleStreams()
	if err != nil {
		restore()
		t.Skipf("this test process has no console of its own to be repointed at: %v", err)
	}
	defer restore()
	// GetConsoleMode answers on the new os.Stdin: the streams now name a
	// real console, which is the whole property the stub hands the program.
	var mode uint32
	if err := syscall.GetConsoleMode(syscall.Handle(os.Stdin.Fd()), &mode); err != nil {
		t.Errorf("the repointed stdin is not a console: %v", err)
	}
}

// TestTheConsoleRelayCarriesTheChildsRenderedOutput proves the plumbing
// built here, end to end inside one process and one account: the console
// exists, the child started by the same proc.RunWithConsole the stub will
// call is born attached to it, and the child's rendered output arrives on
// the relay's output pipe as VT bytes. It does not prove the account
// crossing -- that was measured live under a real sandbox account,
// docs/investigations/2026-09-20-same-window-console.md section 4 -- and it
// does not prove the relay across the operator bridge, which is a later
// task. The child is cmd.exe; what it echoes reaches the console a real
// terminal program would see, and arrives as the same rendered VT a real
// terminal's pixels start life as.
//
// The echo goes through the console device by name rather than a standard
// handle, and that redirect is measured honesty, not a dodge: this test
// process has a console of its own (go test's), and in that shape a plain
// `echo` landed on the test harness while the relay never saw it -- measured,
// in this test's first draft, with the captured stream dumped both ways.
// What the child's own console is, is not in question: `> CON` opens the
// devices of the console the child was born attached to, which is exactly
// what a real terminal program's C runtime does when its inherited standard
// handles are unusable -- the documented CRT-startup gap. Under the real
// stub the host has no console at all (GetConsoleWindow 0x0,
// docs/investigations/2026-09-20-same-window-console.md section 4), and that
// gap is the shape the stub's child actually sits in.
func TestTheConsoleRelayCarriesTheChildsRenderedOutput(t *testing.T) {
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	relay, err := takeConsoleRelay()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.close()
	// Drained continuously from the moment the console exists: reading only
	// after the child ends would deadlock against a child whose output fills
	// the pipe before it exits -- the record internal/e2e/teardown_test.go
	// keeps for the same shape.
	var out bytes.Buffer
	var outMu sync.Mutex
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 4096)
		for {
			n, readErr := relay.output.Read(buf)
			if n > 0 {
				outMu.Lock()
				out.Write(buf[:n])
				outMu.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}()
	captured := func() string {
		outMu.Lock()
		defer outMu.Unlock()
		return out.String()
	}

	var own syscall.Token
	// The child runs under the current, same-account, unrestricted token;
	// the account crossing is not this test's business.
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()

	// Twenty-one characters, under the console's 80 columns, so the echo
	// cannot be rewrapped in half.
	const marker = "WUSERBOX-CONPTY-RELAY"
	// The echo goes through the console by name; see this test's doc comment
	// for why a standard handle would point somewhere else entirely.
	code, err := proc.RunWithConsole(own, `C:\Windows\System32\cmd.exe /c echo `+marker+`> CON`, t.TempDir(), relay.hpc)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("the child ended with exit code %d, want 0", code)
	}
	// The child is done, but its conhost renders on a timer of its own and
	// holds the last write end of the output pipe: ending the console the
	// instant the child exits can drop the rendered echo on the floor
	// (measured -- the VT startup sequences arrive, the echo does not). Wait
	// briefly for it, then close: closing the console is what lets the drain
	// reach EOF. close is safe to call twice -- the deferred call finds
	// nothing left to do.
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(captured(), marker) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	relay.close()
	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		t.Fatalf("the relay's output never reached EOF; captured so far:\n%s", captured())
	}
	if got := captured(); !strings.Contains(got, marker) {
		t.Errorf("the relay's output never named the marker; captured:\n%s", got)
	}
}

// TestTheRelayPipeEndsStayOutOfTheInheritancePath measures the handle
// hygiene takeConsoleRelay's comment claims, the way the proc package
// measures the same claim about its own bridge pipes: the relay's two kept
// ends -- the input end keystrokes are written through and the output end
// rendered bytes are read from -- stay in this process, and neither may
// reach a child it was never meant for through ambient inheritance. What
// makes the check worth its own test is that this package's noInherit is
// its own copy of the hygiene, not internal/win/proc's, and no other test
// here reads back what that copy did at this call site -- the same standard
// docs/reviews/sandbox-security-review-2026-09-19.md's P2-1 set and
// TestNoInheritStripsTheInheritFlag holds the proc package's copy to.
func TestTheRelayPipeEndsStayOutOfTheInheritancePath(t *testing.T) {
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	relay, err := takeConsoleRelay()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.close()
	for _, end := range []struct {
		name string
		file *os.File
	}{
		{"the relay's input end", relay.input},
		{"the relay's output end", relay.output},
	} {
		var flags uint32
		if r, _, callErr := procGetHandleInformation.Call(end.file.Fd(), uintptr(unsafe.Pointer(&flags))); r == 0 {
			t.Fatalf("GetHandleInformation on %s: %v", end.name, callErr)
		}
		if flags&handleFlagInherit != 0 {
			t.Errorf("%s is still inheritable; the relay's pipe ends were meant to stop at this process", end.name)
		}
	}
}

// TestAStubAskedForTwoConsolesAtOnceRefuses pins the mutual-exclusion
// policy: one program, one console, and the stub refuses the contradiction
// rather than resolving it silently. The refusal is the usage code because a
// contradictory request is a malformed request. Calling Stub in-process is
// safe here because the check sits before the token is built and before
// anything is started: it reads the two env vars and returns.
func TestAStubAskedForTwoConsolesAtOnceRefuses(t *testing.T) {
	t.Setenv(proc.EnvOwnConsole, "1")
	t.Setenv(proc.EnvConsoleRelay, "1")
	err := Stub([]string{"S-1-5-21-1-2-3-1004", "some-read-group", "cmd /c echo hi"})
	if err == nil {
		t.Fatal("the stub accepted two consoles for one program")
	}
	if got := exit.Of(err); got != exit.Usage {
		t.Errorf("the refusal carried exit code %v, want %v (usage)", got, exit.Usage)
	}
	for _, named := range []string{proc.EnvOwnConsole, proc.EnvConsoleRelay} {
		if !strings.Contains(err.Error(), named) {
			t.Errorf("the refusal does not name %s: %v", named, err)
		}
	}
}

// TestTheRelayPumpCarriesRenderedBytesOutAndKeystrokesIn measures both
// directions of pumpRelay against one live pseudo console: a child sits in
// the relay's console waiting on a line, the keystrokes enter through the
// stdin the pump reads, and what the console makes of them -- the child's
// answer to the line -- comes back through the stdout the pump writes. It
// is the stub's half of the relay inside one process and one account; the
// account crossing itself is internal/e2e's business.
func TestTheRelayPumpCarriesRenderedBytesOutAndKeystrokesIn(t *testing.T) {
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	relay, err := takeConsoleRelay()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.close()
	// A stand-in operator console: keystrokes arrive on keyRead, rendered
	// bytes leave on screenWrite. pumpRelay is handed the swapped streams
	// exactly as Stub hands it the real ones.
	keyRead, keyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer keyWrite.Close()
	screenRead, screenWrite, err := os.Pipe()
	if err != nil {
		keyRead.Close()
		t.Fatal(err)
	}
	defer screenRead.Close()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = keyRead, screenWrite
	defer func() {
		os.Stdin, os.Stdout = oldIn, oldOut
		keyRead.Close()
	}()
	pump := pumpRelay(relay, os.Stdout, os.Stdin)
	// Queued before the child exists, so nothing in the test's timing
	// decides whether the console ever sees them.
	const keys = "WUSERBOX-KEYS"
	if _, err := keyWrite.WriteString(keys + "\r\n"); err != nil {
		t.Fatal(err)
	}
	// Drained continuously from before the child starts: reading only
	// after it ends would risk a full pipe blocking the very rendering
	// this test waits for.
	var out bytes.Buffer
	var outMu sync.Mutex
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 4096)
		for {
			n, readErr := screenRead.Read(buf)
			if n > 0 {
				outMu.Lock()
				out.Write(buf[:n])
				outMu.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}()
	captured := func() string {
		outMu.Lock()
		defer outMu.Unlock()
		return out.String()
	}

	var own syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()

	// A child that reads one line from its own console and answers on it,
	// both through the console by name -- the shape a real terminal
	// program's C runtime reaches under the stub, where the inherited
	// standard handles are the documented CRT-startup gap. The answer
	// must contain the expanded value, which proves the line traveled
	// keystroke -> console -> child and not only child -> console.
	//
	// The gap has to be built here rather than inherited, because `go test`
	// runs this process with valid, inheritable pipe handles of its own, and
	// a child started while those stand simply inherits them -- measured:
	// the child's echo and set /p's prompt landed on the test harness, and
	// set /p read the harness's empty stdin, leaving its variable unset.
	// The real stub has no console behind it and its GetStdHandle values are
	// what the CRT refuses, so the CRT's own CONIN$ fallback is what reads
	// the relayed keystrokes; clearing this process's standard handles for
	// the length of the start is what puts the child in that same shape.
	// RunWithConsole now shapes the child at the launch itself -- every child
	// starts with NULL standard handles -- so this clearing is belt and braces
	// rather than load-bearing; it stays because explicit is cheaper than
	// subtle. The launch-side fix is
	// TestRunWithConsoleGivesTheChildAWorkingGetStdHandle's measurement.
	const stdInputHandle, stdOutputHandle, stdErrorHandle = ^uintptr(9), ^uintptr(10), ^uintptr(11)
	savedIn, _, _ := procGetStdHandle.Call(stdInputHandle)
	savedOut, _, _ := procGetStdHandle.Call(stdOutputHandle)
	savedErr, _, _ := procGetStdHandle.Call(stdErrorHandle)
	procSetStdHandle.Call(stdInputHandle, 0)
	procSetStdHandle.Call(stdOutputHandle, 0)
	procSetStdHandle.Call(stdErrorHandle, 0)
	defer func() {
		procSetStdHandle.Call(stdInputHandle, savedIn)
		procSetStdHandle.Call(stdOutputHandle, savedOut)
		procSetStdHandle.Call(stdErrorHandle, savedErr)
	}()
	const answer = "GOT=" + keys
	code, err := proc.RunWithConsole(own,
		`C:\Windows\System32\cmd.exe /v:on /c "set /p V= & echo GOT=!V!> CON"`,
		t.TempDir(), relay.hpc)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("the child ended with exit code %d, want 0", code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(captured(), answer) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	relay.close()
	// The pump is now tracked, so the test awaits it before closing the
	// read side its own drain guards: relay.close breaks the pump's source
	// -- the established close-under-reader shape this package's drains
	// use -- and the await proves every byte it read was written into
	// screenWrite before that read side is closed and the drain below can
	// reach EOF. The pump ends with a read error there because the test
	// forced it, and the test does not consult the pump's error.
	pump.drained.Wait()
	// The pump's output side is the last writer on screenWrite, and the
	// relay's close is what ends it: closing the write end here is what
	// lets the drain below reach EOF at all, the same moment the stub's
	// own exit would hand the caller's drain one.
	screenWrite.Close()
	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		t.Fatalf("the relay's output never reached EOF; captured so far:\n%s", captured())
	}
	if got := captured(); !strings.Contains(got, answer) {
		t.Errorf("the relayed console never answered %q; captured:\n%s", answer, got)
	}
}

// TestAResizeMessageReshapesTheRelayedConsole is the live measurement that a
// resize message reaches the child's console through the production pump:
// messages are queued on the relay's third pipe, pumpRelayResizes -- the
// same loop the real stub runs -- reads them, and a child that polls its own
// console's window size writes what it measured into a file this test reads.
// It does not prove the account crossing -- the sibling tests' caveat, and
// internal/e2e's business -- and it does not prove the operator side, whose
// loop is measured in internal/win/proc's relay tests. What it proves is the
// link neither of those can see end to end: bytes on the third pipe become
// ResizePseudoConsole on the console the child is attached to.
//
// The first message is all zeros, and the pump must skip it: columns or rows
// zero is "nothing measured", and a pump that forwarded it would ask the
// console for a size nobody measured, while a pump that stopped on it would
// never read the real message queued behind it.
//
// The messages are queued only after the child has marked that it is up and
// polling, and that order is measured, not taste: a resize sent before the
// child exists sometimes never reaches the console the child is born into --
// the first draft of this test measured 80x25 on a run whose message had
// already been consumed -- because a ResizePseudoConsole landing before any
// client is attached can be refused by the pty's conhost, and resize is best
// effort, so a refusal is never retried. The .ready gate in
// internal/win/proc's relay tests is the same lesson. Queued after, the
// resize lands while the child is polling -- the production shape, the
// watcher writing while the program runs -- and the child's poll is the
// determinism, not any test-side sleep: it measures only after the resize
// has landed or 5s have gone. If the resize never lands the file says 80x25
// -- the birth size takeConsoleRelay gives -- and that is the failure. The
// captured stream is not the oracle here, the file is; the drain runs
// anyway, because PowerShell writes to the console and an undrained pipe
// would block it -- the sibling test's reason, unchanged.
func TestAResizeMessageReshapesTheRelayedConsole(t *testing.T) {
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	relay, err := takeConsoleRelay()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.close()
	// Drained continuously from before anything else; see the sibling test
	// for why reading only after the child ends would deadlock.
	var out bytes.Buffer
	var outMu sync.Mutex
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 4096)
		for {
			n, readErr := relay.output.Read(buf)
			if n > 0 {
				outMu.Lock()
				out.Write(buf[:n])
				outMu.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}()
	captured := func() string {
		outMu.Lock()
		defer outMu.Unlock()
		return out.String()
	}

	answerFile := filepath.Join(t.TempDir(), "relay-resize-answer.txt")
	readyFile := filepath.Join(t.TempDir(), "relay-resize-ready.txt")
	// The child marks that it is up, polls its own console until the resize
	// shows up or its 5s run out, then writes what it measured; the paths
	// are single-quoted the way internal/e2e's relay test quotes its paths.
	dir := t.TempDir()
	line := fmt.Sprintf(`powershell.exe -NoProfile -Command "$d = 50; Set-Content -LiteralPath '%s' 'ready'; while ([Console]::WindowWidth -lt 90 -and $d -gt 0) { Start-Sleep -Milliseconds 100; $d-- }; Set-Content -LiteralPath '%s' -Value ([Console]::WindowWidth.ToString() + 'x' + [Console]::WindowHeight)"`, readyFile, answerFile)

	var own syscall.Token
	// The child runs under the current, same-account, unrestricted token;
	// the account crossing is not this test's business.
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	// The gap has to be built here rather than inherited, exactly as the
	// keystroke sibling test records: `go test` runs this process with
	// valid, inheritable pipe handles of its own, and a child started while
	// those stand simply inherits them -- measured in this test's first
	// draft, with [Console]::WindowWidth answering "the handle is invalid"
	// about the harness's pipe and the child's error landing on the test
	// output rather than the relay. Clearing this process's standard
	// handles for the length of the start puts the child in the shape the
	// real stub's child sits in: GetStdHandle invalid at startup, the
	// console devices opened by name, and [Console] reading the
	// pseudoconsole it was born attached to. RunWithConsole now shapes the
	// child at the launch itself -- every child starts with NULL standard
	// handles -- so this clearing is belt and braces rather than
	// load-bearing; it stays because explicit is cheaper than subtle. The
	// launch-side fix is
	// TestRunWithConsoleGivesTheChildAWorkingGetStdHandle's measurement.
	const stdInputHandle, stdOutputHandle, stdErrorHandle = ^uintptr(9), ^uintptr(10), ^uintptr(11)
	savedIn, _, _ := procGetStdHandle.Call(stdInputHandle)
	savedOut, _, _ := procGetStdHandle.Call(stdOutputHandle)
	savedErr, _, _ := procGetStdHandle.Call(stdErrorHandle)
	procSetStdHandle.Call(stdInputHandle, 0)
	procSetStdHandle.Call(stdOutputHandle, 0)
	procSetStdHandle.Call(stdErrorHandle, 0)
	defer func() {
		procSetStdHandle.Call(stdInputHandle, savedIn)
		procSetStdHandle.Call(stdOutputHandle, savedOut)
		procSetStdHandle.Call(stdErrorHandle, savedErr)
	}()
	// RunWithConsole waits the child out, and the messages cannot be queued
	// until the child says it is polling, so the wait runs beside it the
	// way internal/win/proc's relay test runs its afterReady beside its
	// probe.
	started := make(chan error, 1)
	finished := make(chan int, 1)
	go func() {
		got, runErr := proc.RunWithConsole(own, line, dir, relay.hpc)
		started <- runErr
		finished <- got
	}()
	readyDeadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(readyFile); err == nil {
			break
		}
		if time.Now().After(readyDeadline) {
			t.Fatalf("the child never began to poll (%s never appeared); captured:\n%s", readyFile, captured())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The child is polling; now the messages, in the order the pump must
	// cope with them: first the degenerate one it must skip, then the real
	// 101x37, packed little-endian, columns first -- the layout
	// encodeResize writes on the operator side, and the one wire format
	// both ends share.
	resizedRead, resizedWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer resizedWrite.Close()
	degenerate := make([]byte, proc.ResizeMessageLen)
	if _, err := resizedWrite.Write(degenerate); err != nil {
		t.Fatal(err)
	}
	message := make([]byte, proc.ResizeMessageLen)
	binary.LittleEndian.PutUint16(message[0:], 101)
	binary.LittleEndian.PutUint16(message[2:], 37)
	if _, err := resizedWrite.Write(message); err != nil {
		t.Fatal(err)
	}
	pumpRelayResizes(relay, resizedRead)

	if err := <-started; err != nil {
		t.Fatal(err)
	}
	code := <-finished
	if code != 0 {
		t.Fatalf("the child ended with exit code %d, want 0; captured:\n%s", code, captured())
	}
	answer, err := os.ReadFile(answerFile)
	if err != nil {
		t.Fatalf("the child wrote no answer file: %v; captured:\n%s", err, captured())
	}
	if got := strings.TrimSpace(string(answer)); got != "101x37" {
		t.Fatalf("the relayed console measured %q, want 101x37 -- a wrong size says the resize message never took; captured:\n%s", got, captured())
	}
	// Closing the console is what lets the drain below reach EOF, the
	// sibling pattern; close is safe to call twice -- the deferred call
	// finds nothing left to do.
	relay.close()
	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		t.Fatalf("the relay's output never reached EOF; captured so far:\n%s", captured())
	}
}

// barrierWriter is a writer whose first Write blocks until release is
// closed, and which keeps everything it is finally handed. It models the
// outer bridge pipe's reader deliberately holding the stream back after the
// child has exited -- the consumer side of the P2-1 race: conhost's last
// rendered bytes are already in this process's hands, the copy into the
// caller's bridge cannot return because the reader will not take them, and
// the only honest completion signal is that copy coming back.
type barrierWriter struct {
	mu      sync.Mutex
	held    bytes.Buffer
	release chan struct{}
}

func (w *barrierWriter) Write(p []byte) (int, error) {
	<-w.release
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.held.Write(p)
}

func (w *barrierWriter) captured() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.held.Bytes()...)
}

// goneBridgeWriter is a consumer whose very first Write fails: a bridge
// pipe whose reader end went away mid-carry.
type goneBridgeWriter struct{}

func (goneBridgeWriter) Write(p []byte) (int, error) { return 0, errBridgeGone }

// errBridgeGone is what goneBridgeWriter fails with, and what the test
// below demands the pump's recorded error name.
var errBridgeGone = errors.New("the consumer's bridge went away mid-carry")

// TestTheRelayPumpHoldsTheRunUntilItsConsumerHasSwallowedTheOutput pins what
// the old fixed 250ms grace could only approximate: the run's completion --
// finish returning here, standing in for the stub's os.Exit -- cannot
// happen while the consumer still holds the stream back. The barrier stands
// for a bridge reader that stops reading exactly when the child exits, the
// shape P2-1 measured: every byte is already waiting in this process, the
// write into the consumer cannot return, and no fixed pause can cover a
// hold whose length the consumer alone decides -- which is why the negative
// window below, 400ms, is deliberately longer than the 250ms the old grace
// slept: no sleep can satisfy this test, only the release does. What finish
// waits for is delivery and not merely the pipe's end, because io.Copy's
// return is a completed last Write into the consumer, and the equality
// check is the proof of it: the full payload crossed, nothing dropped by
// the race the old code narrowed but never closed.
//
// What this test does not measure is a real conhost; the sibling ConPTY
// tests cover that. The relay here is hand-built with hpc left 0, which
// makes finish's closeConsole a no-op on purpose: nothing in this test may
// depend on a console existing or on ClosePseudoConsole's timing -- the
// property under test is the drain, and the drain alone.
func TestTheRelayPumpHoldsTheRunUntilItsConsumerHasSwallowedTheOutput(t *testing.T) {
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// The relay's input end only has to be closable -- finish closes it
	// first -- so a throwaway pipe stands in; the read end is closed here
	// and the write end belongs to the relay.
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		outRead.Close()
		outWrite.Close()
		t.Fatal(err)
	}
	defer inRead.Close()
	relay := &consoleRelay{input: inWrite, output: outRead}
	consumer := &barrierWriter{release: make(chan struct{})}
	// The empty reader ends the input loop at its first Read, so the only
	// goroutine still doing anything is the tracked drain.
	pump := pumpRelay(relay, consumer, strings.NewReader(""))
	payload := bytes.Repeat([]byte("WUSERBOX-DRAIN-BARRIER/"), 400)
	if _, err := outWrite.Write(payload); err != nil {
		t.Fatal(err)
	}
	// EOF is now already waiting behind the data, so the drain's one
	// remaining obstacle is the barrier -- the consumer holding the
	// stream back after the child would have exited.
	if err := outWrite.Close(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- pump.finish(relay) }()
	select {
	case err := <-finished:
		t.Fatalf("finish reported the run finished before the consumer released the output: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	close(consumer.release)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("finish returned an error once the consumer had swallowed the output: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("finish never returned after the consumer released the output")
	}
	if got := consumer.captured(); !bytes.Equal(got, payload) {
		offset := -1
		limit := len(got)
		if len(payload) < limit {
			limit = len(payload)
		}
		for i := 0; i < limit; i++ {
			if got[i] != payload[i] {
				offset = i
				break
			}
		}
		t.Fatalf("the consumer swallowed %d of the %d bytes (first differing offset %d); the delivery was not complete",
			len(got), len(payload), offset)
	}
	// Twice-safe: finish's success path already closed the relay.
	relay.close()
}

// TestARelayConsumerThatStopsMidDrainIsReportedNotSwallowed pins the other
// half of the tracked drain: a delivery failure comes back as an error,
// neither as success nor as silence. The pump this package shipped first
// discarded io.Copy's result exactly, so a consumer whose bridge died
// mid-carry was indistinguishable from a delivery that completed -- a
// silent truncation behind the program's own exit code, the shape P2-1 is
// about. The assert here pins the surfacing the recorded error now gives.
// The production consequence is the stub returning it: the message crosses
// the stderr bridge, a different pipe from the stdout one that may itself
// be the broken half, and wuserbox pays for it with its own failure exit
// code -- the signal that needs no working pipe.
func TestARelayConsumerThatStopsMidDrainIsReportedNotSwallowed(t *testing.T) {
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		outRead.Close()
		outWrite.Close()
		t.Fatal(err)
	}
	defer inRead.Close()
	relay := &consoleRelay{input: inWrite, output: outRead}
	pump := pumpRelay(relay, goneBridgeWriter{}, strings.NewReader(""))
	payload := bytes.Repeat([]byte("WUSERBOX-DRAIN-FAILURE/"), 400)
	if _, err := outWrite.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := outWrite.Close(); err != nil {
		t.Fatal(err)
	}
	// Inline, deliberately: the drain fails on its first Write, so finish
	// returns promptly -- the call not hanging is the no-hang proof, and
	// nothing in the assertion depends on timing.
	err = pump.finish(relay)
	if err == nil {
		t.Fatal("finish reported success although the consumer's bridge failed mid-drain")
	}
	if !errors.Is(err, errBridgeGone) {
		t.Fatalf("finish's error does not name the consumer's failure: %v", err)
	}
	relay.close()
}

// TestTheRelayPumpGivesUpOnADrainOnlyPastTheCeiling measures the
// exceptional path the ceiling exists to bound: a drain that never ends,
// because the consumer never reads and nothing closes the pipe. The bound
// must be reachable -- the alternative to giving up is a stub that hangs
// against a run waiting for it to die -- and reaching it must still be an
// error, not a success with truncated output: the report says the run's
// output may be incomplete, which is the honest verdict, and the caller
// turns it into a failure exit code rather than letting a short delivery
// pass for a whole one.
//
// The ceiling is shrunk to 200ms to keep the model deterministic; nothing
// else about the shape differs from production. The second half measures
// that giving up on the wait did not abandon the drain: the tracked
// goroutine is still awaited once the consumer lets the stream go, and
// every byte crosses then. finish deliberately does not close the read end
// under the wedged drain -- closing a handle a synchronous read is blocked
// in is undefined ground -- so this test releases the barrier instead, the
// same way the process's own death would end the pipe.
func TestTheRelayPumpGivesUpOnADrainOnlyPastTheCeiling(t *testing.T) {
	oldCeiling := relayDrainCeiling
	relayDrainCeiling = 200 * time.Millisecond
	defer func() { relayDrainCeiling = oldCeiling }()
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		outRead.Close()
		outWrite.Close()
		t.Fatal(err)
	}
	defer inRead.Close()
	relay := &consoleRelay{input: inWrite, output: outRead}
	consumer := &barrierWriter{release: make(chan struct{})}
	pump := pumpRelay(relay, consumer, strings.NewReader(""))
	payload := bytes.Repeat([]byte("WUSERBOX-DRAIN-CEILING/"), 400)
	if _, err := outWrite.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := outWrite.Close(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- pump.finish(relay) }()
	var finishErr error
	select {
	case finishErr = <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("finish never gave up on the drain that never ended")
	}
	if finishErr == nil {
		t.Fatal("finish reported success although the drain never ended")
	}
	if !strings.Contains(finishErr.Error(), "incomplete") {
		t.Fatalf("the ceiling's error does not say the output may be incomplete: %v", finishErr)
	}
	// The consumer is still holding the stream back at this point -- the
	// ceiling, not delivery, is what finish returned on. Releasing it is
	// what lets the drain move, the way the process's own death would
	// have ended the pipe, and the tracked drain must still be awaited
	// to its end.
	close(consumer.release)
	allDone := make(chan struct{})
	go func() {
		pump.drained.Wait()
		close(allDone)
	}()
	select {
	case <-allDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the tracked drain never ended even after the consumer released the output")
	}
	if got := consumer.captured(); !bytes.Equal(got, payload) {
		t.Fatalf("the consumer swallowed %d of the %d bytes; the drain dropped bytes after the ceiling",
			len(got), len(payload))
	}
	relay.close()
}

// TestTheRelayFinishDoesNotRestOnClosePseudoConsolesReturn is the live
// ConPTY measurement of finish's order: ClosePseudoConsole is called inside
// finish, before the barrier ever releases, and its return is never
// consulted -- the verdict still waits for the child's rendered marker to
// be fully delivered to the consumer. What this machine cannot do is
// reproduce 24H2-specific timing on demand -- its Windows generation is
// whatever it is -- so what is pinned is structural: the child's exit is
// the only thing waited for before finish starts, which is exactly the
// shape the fixed stub runs; the barrier holds the consumer back past both
// the child's exit and the EOF ending the console produces; and finish
// still does not return until everything the drain read has crossed. On a
// Windows generation where the call returns before the pty has drained
// internally, the drain-after-close this test exercises is what carries the
// tail -- the doc's own guidance is to keep reading the pipe, and that is
// the reading this verdict waits past the call's return for.
func TestTheRelayFinishDoesNotRestOnClosePseudoConsolesReturn(t *testing.T) {
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	relay, err := takeConsoleRelay()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.close()
	consumer := &barrierWriter{release: make(chan struct{})}
	// No keystrokes exist in this test; the empty reader ends the input
	// loop at its first Read.
	pump := pumpRelay(relay, consumer, strings.NewReader(""))
	var own syscall.Token
	// The child runs under the current, same-account, unrestricted token;
	// the account crossing is not this test's business.
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	// The same shape as the carries-the-output sibling: twenty-one
	// characters, under the console's 80 columns, echoed through the
	// console by name -- see that test's doc comment for why a standard
	// handle would point somewhere else entirely.
	const marker = "WUSERBOX-CONPTY-RELAY"
	// RunWithConsole returns when the child has exited, and nothing else
	// is waited for before finish starts -- no marker watch, no pause:
	// exactly the moment the fixed stub used to begin its grace.
	code, err := proc.RunWithConsole(own, `C:\Windows\System32\cmd.exe /c echo `+marker+`> CON`, t.TempDir(), relay.hpc)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("the child ended with exit code %d, want 0", code)
	}
	finished := make(chan error, 1)
	go func() { finished <- pump.finish(relay) }()
	// finish has ended the console by now, so ClosePseudoConsole has
	// returned and the source pipe may well be at EOF -- and the verdict
	// must still not land while the consumer holds the stream back. The
	// 300ms window is a negative assertion, not an oracle: no pause covers
	// a hold whose length the consumer alone decides.
	select {
	case err := <-finished:
		t.Fatalf("finish returned within 300ms, before the consumer released the output: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(consumer.release)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("finish returned an error once the consumer had swallowed the output: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("finish never returned after the consumer released the output")
	}
	if got := string(consumer.captured()); !strings.Contains(got, marker) {
		t.Errorf("the relayed console's marker never reached the consumer; captured:\n%s", got)
	}
	// Twice-safe with the deferred close above.
	relay.close()
}

// TestAResizeHeldBetweenTheHandleAndTheWinAPICallIsOrderedBeforeTheClose is
// the P1-2 close test, deterministic and console-free. The relay is
// hand-built with a fake handle -- both hooked WinAPI calls intercept
// everything, so the value is never aimed at anything real -- and the
// resize pump is fed one real message whose call is held at the gate
// exactly where the native call would sit: past the handle read, before
// the call, the instant the old race lived in. finish runs against it
// while the resize stands there. Under the old shape the close freed the
// console at that instant and the gate's release would then have fired
// ResizePseudoConsole against the freed handle; under the new one the
// close cannot pass an in-flight resize -- closeConsole waits it out --
// and finish's ceiling returns first, because the ceiling now covers the
// close's own wait too. The assertions are the order itself, not a
// usually-fine outcome: the close never begins while the resize is held,
// the resize the gate releases is aimed at the still-live handle and
// returns before the free begins, the free happens exactly once, and a
// resize asked for after the closed state is set is a no-op that neither
// calls nor blocks.
func TestAResizeHeldBetweenTheHandleAndTheWinAPICallIsOrderedBeforeTheClose(t *testing.T) {
	oldCeiling := relayDrainCeiling
	relayDrainCeiling = 300 * time.Millisecond
	// The restores are t.Cleanups, registered so they run after the
	// test's own defers and in this order: quiesce first, then the
	// hooks, then the ceiling. A test that dies mid-flight must not
	// restore a hook a still-running goroutine is about to read -- that
	// is a data race on the package var standing in for the seam -- so
	// the quiesce is registered last and runs first, and on the success
	// path it is a no-op.
	t.Cleanup(func() { relayDrainCeiling = oldCeiling })
	const fakeHPC = syscall.Handle(0x00C0FFEE)
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outWrite.Close()
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		outRead.Close()
		outWrite.Close()
		t.Fatal(err)
	}
	defer inRead.Close()
	relay := &consoleRelay{hpc: fakeHPC, input: inWrite, output: outRead}

	// The hooks stand where the native calls sit. The resize records the
	// handle it was aimed at -- the value is what the race is about --
	// and holds until the gate; the close records the handle it frees,
	// so "the close began" means exactly "the console was freed".
	var (
		mu      sync.Mutex
		aimedAt []syscall.Handle
		events  []string
	)
	resizeEntered := make(chan struct{}, 1)
	closeBegan := make(chan struct{}, 1)
	gate := make(chan struct{})
	oldResize, oldClose := resizePseudoConsole, closePseudoConsole
	resizePseudoConsole = func(hpc syscall.Handle, cols, rows int) {
		mu.Lock()
		aimedAt = append(aimedAt, hpc)
		events = append(events, fmt.Sprintf("resize %dx%d call", cols, rows))
		mu.Unlock()
		resizeEntered <- struct{}{}
		<-gate
		mu.Lock()
		events = append(events, "resize call returned")
		mu.Unlock()
	}
	closePseudoConsole = func(hpc syscall.Handle) {
		mu.Lock()
		aimedAt = append(aimedAt, hpc)
		events = append(events, "close call")
		mu.Unlock()
		closeBegan <- struct{}{}
	}
	t.Cleanup(func() { resizePseudoConsole, closePseudoConsole = oldResize, oldClose })
	releaseGate := new(sync.Once)
	t.Cleanup(func() {
		releaseGate.Do(func() { close(gate) })
	})

	// Nothing may reach a consumer and the input loop ends on its empty
	// reader, the siblings' shape; the drain itself stays wedged on the
	// never-written, never-closed output pipe, so finish's verdict can
	// come only from the ceiling -- which is the point.
	pump := pumpRelay(relay, &bytes.Buffer{}, strings.NewReader(""))
	resizedRead, resizedWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer resizedWrite.Close()
	pumpRelayResizes(relay, resizedRead)
	message := make([]byte, proc.ResizeMessageLen)
	binary.LittleEndian.PutUint16(message[0:], 101)
	binary.LittleEndian.PutUint16(message[2:], 37)
	if _, err := resizedWrite.Write(message); err != nil {
		t.Fatal(err)
	}
	// The resize is awaited to the gate BEFORE finish runs. At the gate
	// it has already passed the closed check and counted itself
	// in-flight -- exactly the state the test is about -- and no
	// scheduling coin can take that away: started the other way round,
	// finish's close could win the handle first and turn the resize
	// into the no-op a closed relay rightly owes, failing this test on
	// a loaded machine with nothing wrong at all. finish runs inline:
	// its ceiling brings it back in ~300ms, at the gate's mercy only.
	select {
	case <-resizeEntered:
	case <-time.After(10 * time.Second):
		t.Fatal("the resize message never reached the hooked WinAPI call")
	}
	finishErr := pump.finish(relay)
	if finishErr == nil {
		t.Fatal("finish reported success while a resize was in flight and the close was parked behind it")
	}
	if !strings.Contains(finishErr.Error(), "incomplete") {
		t.Fatalf("the ceiling's error does not say the output may be incomplete: %v", finishErr)
	}
	// The close must not have begun while the resize held the call: the
	// free waits behind the in-flight resize, by construction, and the
	// gate is still shut.
	select {
	case <-closeBegan:
		t.Fatal("the console was freed while a resize call was still in flight against it")
	default:
	}
	// A resize asked for now -- the closed state is already set -- is
	// refused without a call and without waiting on the close parked
	// behind the gate.
	refused := make(chan struct{})
	go func() { relay.resize(20, 5); close(refused) }()
	select {
	case <-refused:
	case <-time.After(5 * time.Second):
		t.Fatal("a resize on a closing relay waited on the teardown instead of being refused")
	}
	mu.Lock()
	aimed := len(aimedAt)
	mu.Unlock()
	if aimed != 1 {
		t.Fatalf("the refused resize reached the WinAPI call %d extra times", aimed-1)
	}
	// Release the gate: the in-flight resize returns against the handle
	// it read while the console was still alive, and only then does the
	// close reach the free.
	releaseGate.Do(func() { close(gate) })
	select {
	case <-closeBegan:
	case <-time.After(10 * time.Second):
		t.Fatal("the close never reached the console after the in-flight resize returned")
	}
	mu.Lock()
	order := append([]string(nil), events...)
	handles := append([]syscall.Handle(nil), aimedAt...)
	mu.Unlock()
	returned := slices.Index(order, "resize call returned")
	freedAt := slices.Index(order, "close call")
	if returned < 0 || freedAt < 0 || returned > freedAt {
		t.Fatalf("the in-flight resize and the free ran out of order: %v", order)
	}
	for _, h := range handles {
		if h != fakeHPC {
			t.Fatalf("a WinAPI call was aimed at handle %#x, not the live one", h)
		}
	}
	// End the drain the way the process's own death would -- data and
	// then the pipe's end, so the blocked read unblocks before the read
	// end is ever closed -- and then close the relay itself: twice-safe,
	// and the free it finds already done must not happen a second time.
	if _, err := outWrite.Write([]byte("WUSERBOX-TEARDOWN")); err != nil {
		t.Fatal(err)
	}
	if err := outWrite.Close(); err != nil {
		t.Fatal(err)
	}
	allDone := make(chan struct{})
	go func() {
		pump.drained.Wait()
		close(allDone)
	}()
	select {
	case <-allDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the tracked drain never ended after the output pipe did")
	}
	relay.close()
	mu.Lock()
	closeCount := 0
	for _, e := range events {
		if e == "close call" {
			closeCount++
		}
	}
	mu.Unlock()
	if closeCount != 1 {
		t.Fatalf("the console was freed %d times, want exactly once", closeCount)
	}
}

// TestAFinishWhoseConsoleCloseHangsIsBoundedByTheCeilingNotByTheClose is
// the structural half of the P1-1 close test. The old finish called
// closeConsole synchronously and only then started the clock, so a
// ClosePseudoConsole that never returned -- which before Windows 11 24H2
// is exactly what Microsoft's contract says one with nowhere to drain can
// do -- held the whole run past any ceiling. Here the hooked close is that
// hang, stood exactly where the native call sits, and the drain is wedged
// on its own -- a never-written, never-closed pipe -- so finish's only way
// out is the ceiling. The assertions measure the shape, not a usually-fine
// outcome: the close enters the native call, and finish still returns
// while it is in there -- the deadline raced the close, it did not stand
// behind it -- with the honest possibly-incomplete verdict rather than a
// silent success; a second closeConsole answers at once instead of
// queueing behind the hung one; and once the gate lets the call finish it
// ran exactly once.
func TestAFinishWhoseConsoleCloseHangsIsBoundedByTheCeilingNotByTheClose(t *testing.T) {
	oldCeiling := relayDrainCeiling
	relayDrainCeiling = 300 * time.Millisecond
	// Same cleanup order as the sibling test: quiesce first, then the
	// hooks, then the ceiling, so a mid-flight death never restores a
	// hook a still-running goroutine is about to read.
	t.Cleanup(func() { relayDrainCeiling = oldCeiling })
	const fakeHPC = syscall.Handle(0x00C0FFEF)
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outWrite.Close()
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		outRead.Close()
		outWrite.Close()
		t.Fatal(err)
	}
	defer inRead.Close()
	relay := &consoleRelay{hpc: fakeHPC, input: inWrite, output: outRead}
	// The drain is wedged from birth -- nothing is ever written to the
	// output pipe and nothing ever closes it -- so no drain verdict can
	// end this teardown; the ceiling is the only way out, and the close
	// is hung for as long as the gate says so.
	pump := pumpRelay(relay, &bytes.Buffer{}, strings.NewReader(""))
	var (
		mu         sync.Mutex
		closeCount int
		closeHPC   syscall.Handle
	)
	closeStarted := make(chan struct{}, 1)
	closeEnded := make(chan struct{}, 1)
	gate := make(chan struct{})
	oldClose := closePseudoConsole
	closePseudoConsole = func(hpc syscall.Handle) {
		mu.Lock()
		closeCount++
		closeHPC = hpc
		mu.Unlock()
		closeStarted <- struct{}{}
		<-gate
		closeEnded <- struct{}{}
	}
	t.Cleanup(func() { closePseudoConsole = oldClose })
	releaseGate := new(sync.Once)
	t.Cleanup(func() {
		releaseGate.Do(func() { close(gate) })
	})
	// finish runs inline and its ceiling brings it back; the close's
	// arrival at the hooked call is checked afterwards, from the
	// buffered signal the wrapper left.
	finishErr := pump.finish(relay)
	select {
	case <-closeStarted:
	default:
		t.Fatal("the close never reached the hooked ClosePseudoConsole")
	}
	if finishErr == nil || !strings.Contains(finishErr.Error(), "incomplete") {
		t.Fatalf("the ceiling's verdict with the close hung inside the native call: %v", finishErr)
	}
	// finish is back while the close is still parked inside the call --
	// that is the structural property itself: the deadline counted
	// against the close, not after it.
	select {
	case <-closeEnded:
		t.Fatal("the hooked close returned before the gate moved -- the hang was never held")
	default:
	}
	// Nothing re-enters the blocking close: a second closeConsole --
	// the shape any deferred cleanup would take -- answers at once
	// instead of queueing behind the hung one, and the console is still
	// freed exactly once.
	reentered := make(chan struct{})
	go func() { relay.closeConsole(); close(reentered) }()
	select {
	case <-reentered:
	case <-time.After(5 * time.Second):
		t.Fatal("a second closeConsole waited on the close that is still hung inside the native call")
	}
	mu.Lock()
	count := closeCount
	mu.Unlock()
	if count != 1 {
		t.Fatalf("the console was freed %d times while the close was still hung, want once", count)
	}
	// The close is allowed to finish now; exactly once is still the
	// count, the relay's own close included.
	releaseGate.Do(func() { close(gate) })
	select {
	case <-closeEnded:
	case <-time.After(10 * time.Second):
		t.Fatal("the hooked close never returned even after the gate moved")
	}
	if _, err := outWrite.Write([]byte("WUSERBOX-TEARDOWN")); err != nil {
		t.Fatal(err)
	}
	if err := outWrite.Close(); err != nil {
		t.Fatal(err)
	}
	allDone := make(chan struct{})
	go func() {
		pump.drained.Wait()
		close(allDone)
	}()
	select {
	case <-allDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the tracked drain never ended after the output pipe did")
	}
	relay.close()
	mu.Lock()
	count, hpc := closeCount, closeHPC
	mu.Unlock()
	if count != 1 {
		t.Fatalf("the console was freed %d times in total, want exactly once", count)
	}
	if hpc != fakeHPC {
		t.Fatalf("the close was aimed at handle %#x, not the relay's console", hpc)
	}
}

// prefixBarrierWriter is a consumer that lets the stream's first few
// thousand bytes through and holds everything after that until release.
// The live close test needs a stall that begins mid-carry -- the pipe ends
// up wedged exactly as with barrierWriter, because the pour is far longer
// than the prefix -- but the child's own early words stay readable in the
// prefix, so a child that failed before it ever poured says so where the
// test can quote it.
type prefixBarrierWriter struct {
	release chan struct{}
	prefix  int

	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *prefixBarrierWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	room := w.prefix - w.buf.Len()
	n := 0
	if room > 0 {
		take := p
		if len(take) > room {
			take = take[:room]
		}
		n, _ = w.buf.Write(take)
	}
	if n < len(p) {
		<-w.release
		more, _ := w.buf.Write(p[n:])
		n += more
	}
	return n, nil
}

func (w *prefixBarrierWriter) captured() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

// TestALiveConsolesHungCloseIsStillBoundedByTheCeiling is the live ConPTY
// half of the P1-1 close test, on whatever Windows generation this machine
// runs -- 10.0.19045 at the time of writing, which is before the 24H2
// change, i.e. a machine the documented hang is reproducible on. The child
// announces itself with a file, then pours a bounded few hundred kilobytes
// through the console -- more than the relay's output pipe holds -- while
// the consumer holds the stream back from its very first Write and nothing
// ever drains: pending output with nowhere to go is the exact state the
// ClosePseudoConsole contract says the call can block in. finish starts
// there, and must come back inside the ceiling with the honest
// possibly-incomplete verdict -- whether or not this machine's conhost
// actually wedges the call. If it does, this run bounded the hang itself;
// if it does not, the ceiling still bounded the whole teardown, and the
// log line records which of the two ran, because the two outcomes are
// different evidence and neither may pass silently for the other. The
// resize pump runs through the teardown -- real messages, real
// resizes, against a real console being closed underneath them, ten of
// them spaced wide -- which is what the race detector reads: every access
// to the handle crosses the same ownership or the run trips. The pump is
// gated on the child's ready file and paced deliberately, because the
// storm this fixture first used was measured to take the child's console
// down with it -- a broken fixture failing honestly is still a broken
// fixture.
//
// The consumer stalls mid-carry rather than at its first Write -- the
// first few thousand bytes pass, so a child that failed before it poured
// is quoted by the test instead of being invisible behind the stall -- and
// the pipe still ends up wedged, because the pour is far longer than the
// prefix.
//
// What the test asserts is the bound and the exactly-once free, not the
// whole pour: a client that has already exited while its pipe is stalled
// leaves conhost free to drop its pending tail once the teardown returns
// the pipe, and bytes conhost never wrote are upstream of anything the
// relay can answer for. How much crossed is logged, not asserted.
func TestALiveConsolesHungCloseIsStillBoundedByTheCeiling(t *testing.T) {
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	oldCeiling := relayDrainCeiling
	relayDrainCeiling = 2 * time.Second
	defer func() { relayDrainCeiling = oldCeiling }()
	relay, err := takeConsoleRelay()
	if err != nil {
		t.Fatal(err)
	}
	consumer := &prefixBarrierWriter{release: make(chan struct{}), prefix: 4096}
	pump := pumpRelay(relay, consumer, strings.NewReader(""))
	// The third leg runs through the whole teardown: bounded messages,
	// spaced wide enough that the pump is answering them while the close
	// races the ceiling underneath them.
	resizedRead, resizedWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	pumpRelayResizes(relay, resizedRead)
	stopResizes := make(chan struct{})
	resizesGo := make(chan struct{})
	var resizeWG sync.WaitGroup
	resizeWG.Add(1)
	go func() {
		defer resizeWG.Done()
		// The flood waits for the child the way every relay test in
		// this file waits for it: no resize crosses until the child
		// says it is up. And it is deliberately gentle -- ten resizes,
		// fifty milliseconds apart -- because the storm this test
		// first used was measured, across three fixture shapes, to
		// take the child's console down with it: a console resized
		// flat out under a client attaching to it or pouring through
		// it is a broken fixture, not a measurement. Ten crossings of
		// the ownership are what the race detector reads; it needs
		// the interleavings, not thousands of them.
		<-resizesGo
		message := make([]byte, proc.ResizeMessageLen)
		for i := 0; i < 10; i++ {
			binary.LittleEndian.PutUint16(message[0:], uint16(81+i%20))
			binary.LittleEndian.PutUint16(message[2:], uint16(26+i%10))
			if _, err := resizedWrite.Write(message); err != nil {
				return
			}
			select {
			case <-stopResizes:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	// The close is wrapped, not replaced: the real call still runs, and
	// what the wrapper adds is the evidence -- that it began, when the
	// machine actually gave it back, and that it ran exactly once.
	var (
		closeMu    sync.Mutex
		closeCount int
	)
	closeStarted := make(chan struct{}, 1)
	closeEnded := make(chan struct{}, 1)
	oldClose := closePseudoConsole
	closePseudoConsole = func(hpc syscall.Handle) {
		closeMu.Lock()
		closeCount++
		closeMu.Unlock()
		closeStarted <- struct{}{}
		oldClose(hpc)
		closeEnded <- struct{}{}
	}
	defer func() { closePseudoConsole = oldClose }()
	// The child: announce, then pour. The pour is bounded -- six thousand
	// console lines, far more than the pipe holds -- and nothing waits on
	// the child's exit: a child parked mid-write on a full console is
	// exactly one of the shapes this teardown has to survive, and the
	// buffered channel takes its exit code whenever it comes.
	var own syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	readyFile := filepath.Join(t.TempDir(), "close-ceiling-ready.txt")
	line := fmt.Sprintf(`powershell.exe -NoProfile -Command "Set-Content -LiteralPath '%s' 'ready'; for ($i = 0; $i -lt 6000; $i++) { [Console]::WriteLine('WUSERBOX-CLOSE-CEILING-' + $i) }"`, readyFile)
	// The child's working directory is its own, outside the test's: a
	// child still parked there when the test ends would hold the
	// directory open and turn cleanup into a second failure standing
	// in for the first.
	childDir, err := os.MkdirTemp("", "wuserbox-close-ceiling-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(childDir) }()
	ranWith := make(chan error, 1)
	go func() {
		_, runErr := proc.RunWithConsole(own, line, childDir, relay.hpc)
		ranWith <- runErr
	}()
	readyDeadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Stat(readyFile); err == nil {
			break
		}
		// A child that died before it poured is a failure worth
		// naming now, not at the deadline: its early words are in
		// the prefix the consumer let through.
		select {
		case runErr := <-ranWith:
			t.Fatalf("the child ended before it began to pour: %v; its first words: %q", runErr, consumer.captured())
		default:
		}
		if time.Now().After(readyDeadline) {
			t.Fatalf("the child never began to pour; its first words: %q", consumer.captured())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A beat for the pour to be under way: the child writes into a
	// console whose pipe nobody is taking, so conhost is holding pending
	// output from this instant on -- the state the close blocks in.
	time.Sleep(200 * time.Millisecond)
	// The child is up and pouring; now, and only now, the resizes, so
	// the flood spans the teardown that follows and nothing else.
	close(resizesGo)
	teardownStarted := time.Now()
	finished := make(chan error, 1)
	go func() { finished <- pump.finish(relay) }()
	var finishErr error
	select {
	case finishErr = <-finished:
	case <-time.After(20 * time.Second):
		t.Fatal("finish did not return past the ceiling even with the close running where the deadline can race it")
	}
	teardownTook := time.Since(teardownStarted)
	select {
	case <-closeStarted:
	default:
		t.Fatal("the close never reached the real ClosePseudoConsole")
	}
	if finishErr == nil || !strings.Contains(finishErr.Error(), "incomplete") {
		var childErr error
		select {
		case childErr = <-ranWith:
		default:
		}
		t.Fatalf("finish's verdict with the consumer stalled past the ceiling: %v; the child's exit: %v; its first words: %q", finishErr, childErr, consumer.captured())
	}
	// Which teardown was measured: a close still inside the native call
	// when the ceiling cut in is the documented hang itself, bounded;
	// a close already back means the machine did not wedge it and the
	// ceiling bounded the drain instead. Either is evidence; the log
	// line is what says which one this run produced.
	wasStillInside := true
	select {
	case <-closeEnded:
		wasStillInside = false
	default:
	}
	// Now unstick everything the way the process's own death would, and
	// measure the rest: the consumer lets go, the pour finishes, the
	// close comes back, the drain carries every byte it read.
	close(consumer.release)
	close(stopResizes)
	resizeWG.Wait()
	if err := resizedWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if wasStillInside {
		select {
		case <-closeEnded:
		case <-time.After(30 * time.Second):
			t.Fatal("the console close never came back even after the consumer released the output")
		}
	}
	allDone := make(chan struct{})
	go func() {
		pump.drained.Wait()
		close(allDone)
	}()
	select {
	case <-allDone:
	case <-time.After(30 * time.Second):
		t.Fatal("the tracked drain never ended after the consumer released the output")
	}
	// How much of the pour crossed is reported, not asserted: on this
	// OS generation a client that exits while its pipe is stalled
	// leaves conhost free to drop its pending tail once the teardown
	// gives the pipe back -- observed here as a run whose drain carried
	// only the pipe's own few kilobytes -- and bytes conhost never
	// wrote into the pipe are upstream of anything a relay can answer
	// for. What the relay owes is the bound, the honest verdict and the
	// exactly-once free, asserted above; the tail is Windows' own.
	t.Logf("the drain carried %d of the pour's bytes across after the release", len(consumer.captured()))
	relay.close()
	closeMu.Lock()
	calls := closeCount
	closeMu.Unlock()
	if calls != 1 {
		t.Fatalf("the console was freed %d times, want exactly once", calls)
	}
	var runErr error
	select {
	case runErr = <-ranWith:
	default:
	}
	t.Logf("teardown returned in %s (ceiling %s); the close was still inside the native call when the ceiling cut in: %v; the child's run: %v",
		teardownTook, relayDrainCeiling, wasStillInside, runErr)
}

// TestTheBirthHostsGuardRefusesTheStubWhenTheListCannotBeRead is the P2-1
// close test. The guard used to read every answer but one from
// GetConsoleProcessList as "no console of this process's own", a failed
// read included, and a failed read is exactly the state a guard exists to
// refuse: nothing is known about the birth console's host, and the run
// went on to the token, to Shield and to the program anyway. Here the seam
// fails with an error nothing in production ties to a known shape, and the
// refusal has to travel: shutBirthConsoleHost comes back with that error,
// and Stub -- traced one level up, at the only place production calls the
// guard -- comes back with it too, before the token is built, before Shield
// runs and before any program could start. Calling Stub in-process is safe
// for the same reason TestAStubAskedForTwoConsolesAtOnceRefuses is: the
// refusal sits before anything real happens, and this one sits before even
// the token build.
func TestTheBirthHostsGuardRefusesTheStubWhenTheListCannotBeRead(t *testing.T) {
	injected := errors.New("injected: the console process list cannot be read")
	old := getConsoleProcessList
	getConsoleProcessList = func([]uint32) (int, error) { return 0, injected }
	t.Cleanup(func() { getConsoleProcessList = old })
	// The guard alone first, because the refusal has to start there.
	if err := shutBirthConsoleHost("S-1-5-21-1-2-3-1004"); !errors.Is(err, injected) {
		t.Fatalf("the guard did not report the failed console list read; it returned %v", err)
	}
	// And the bootstrap the guard stands in front of. errors.Is is the
	// oracle, not a bare err != nil: under the old shape the guard returned
	// nil here and Stub died later, of the fake group SID, with a different
	// error -- an error is not evidence of the refusal, the injected one is.
	err := Stub([]string{"S-1-5-21-1-2-3-1004", "some-read-group", "cmd /c echo hi"})
	if !errors.Is(err, injected) {
		t.Fatalf("the stub did not refuse on the failed console list read; it returned %v", err)
	}
	// Shield never ran in this process: the run did not reach the
	// narrowing, let alone the program the narrowing is for.
	shielded, shieldErr := proc.Shielded()
	if shieldErr != nil {
		t.Fatalf("reading this process's shield state: %v", shieldErr)
	}
	if shielded {
		t.Fatal("the run reached Shield past a console list that could not be read")
	}
}

// TestTheBirthHostsGuardKnowsWhatANoConsoleProcessLooksLike pins the one
// failure the guard may spend as a no-op. GetConsoleProcessList never
// answers "no console" with a successful empty list -- every console has at
// least one process attached -- it fails, and the errno is the only thing
// that says what the failure meant. Measured on Windows 10.0.19045 on
// 2026-09-22: a process started with DETACHED_PROCESS, which has no console
// at all, gets a zero answer and ERROR_INVALID_HANDLE, GetConsoleWindow 0.
// That confirmed absence is the shape the callers that arrive some other
// way than the stub -- the tests' subprocesses among them -- legitimately
// produce, and it stays a quiet no-op. Anything else fails closed; that is
// the sibling test's measurement.
func TestTheBirthHostsGuardKnowsWhatANoConsoleProcessLooksLike(t *testing.T) {
	old := getConsoleProcessList
	getConsoleProcessList = func([]uint32) (int, error) { return 0, errorInvalidHandle }
	t.Cleanup(func() { getConsoleProcessList = old })
	account, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := shutBirthConsoleHost(account); err != nil {
		t.Fatalf("a confirmed no-console answer was taken as a refusal: %v", err)
	}
}

// TestTheBirthHostsGuardTreatsAnInheritedConsoleAsAQuietNoOp pins the
// second no-op, the successful call about a console this process does not
// have to itself: more than one process attached is a console inherited
// from somebody else, and no host of this process's can be coming. The
// values cover the shapes the real call produces: an ordinary shared
// console, a crowded one, and consoleListSlots+1 -- the documented
// buffer-too-small answer, a successful call that stored nothing and asked
// for a bigger buffer, about a console that crowded it can only be
// somebody else's.
func TestTheBirthHostsGuardTreatsAnInheritedConsoleAsAQuietNoOp(t *testing.T) {
	account, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, attached := range []int{2, 17, consoleListSlots + 1} {
		old := getConsoleProcessList
		getConsoleProcessList = func([]uint32) (int, error) { return attached, nil }
		if err := shutBirthConsoleHost(account); err != nil {
			t.Errorf("%d processes attached to an inherited console was taken as a refusal: %v", attached, err)
		}
		getConsoleProcessList = old
	}
}

// TestTheBirthHostsGuardShutsTheOneHostOfAConsoleOfItsOwn is the shape the
// production stub arrives in, measured at the seam and in the fixture
// account's seat: the list answers one -- this process alone on a console of
// its own -- and the guard must not read that as a no-op either. The seat is
// built in account_test.go: a dedicated local account, this binary started as
// it with RunAsAccount, the whole choreography below run inside that child,
// every failure a returned error the exit code carries. The old seat was the
// test process's own identity -- the CI runner's built-in Administrator, SID
// ending -500 -- and ShieldConhost's refusal of that SID first, ahead of the
// administrators' allow in the list, is what answered there; from the
// account's seat the door measurements are the direct answer again.
//
// The host the guard shuts is the child's own birth host, and it is real, not
// stood up by a pty: the fixture child is born by RunAsAccount with
// CREATE_NO_WINDOW, which console.go documents as a console with no window,
// hosted by a conhost started before any of this code ran -- the exact shape
// the guard exists for. That is also why this test no longer needs a Windows
// new enough for ConPTY: no pty is built anywhere in it, and the
// CreatePseudoConsole availability skip the pty once required is gone with
// it.
//
// The doors are measured before and after the guard runs: the birth host must
// open for PROCESS_ALL_ACCESS before the shut -- what the shut is measured
// against -- and must open for nothing after it. The list read is pinned at
// the package's getConsoleProcessList seam rather than trusted from the
// machine: the guard's contract is pinned, not the console environment -- the
// honest answer for this child would also be one (its own birth console, one
// process attached), but the injection is what keeps the guard's shape the
// subject instead of the machine's console state.
func TestTheBirthHostsGuardShutsTheOneHostOfAConsoleOfItsOwn(t *testing.T) {
	requireAdministrator(t)
	a := aShutAccount(t, "shld0dea0012")
	_, work, exe := fixtureTree(t, a)
	a.runFixture(t, exe, work, birthFixtureFlag)
}

// birthFixtureFlag dispatches this binary, started as the fixture account, to
// the birth guard's choreography.
const birthFixtureFlag = "-wuserbox-birth-fixture"

// birthFixture is the program this binary becomes when it is started as the
// fixture account. The exit code is the verdict and diagnosis.txt is the
// words that explain a failure -- the same split the relay fixture works on.
func birthFixture(dir string) int {
	if err := measureTheBirthShut(dir); err != nil {
		return fixtureFailed(dir, err)
	}
	return 0
}

// measureTheBirthShut is the guard's whole choreography, in the account's
// seat: the birth host is found by the walk production polls, its one open
// door is measured, the guard runs against the pinned one-process list, and
// the same door is measured shut.
func measureTheBirthShut(dir string) error {
	// The seat here is the fixture account's ordinary token, and a fresh
	// local account is never an administrator unless the fixture made it
	// one -- this fixture does not; the assertion keeps the measurement
	// honest if that ever changes.
	if token.IsAdmin() {
		return errors.New("from an elevated seat the shut's deliberate administrators allow " +
			"answers every door by design, so nothing below would be a measurement")
	}
	// The birth host lags the process it hosts -- measured about 150 ms, the
	// lag console.go polls with this same step and ceiling -- so the walk is
	// polled until it answers exactly one. Zero hosts is the walk not having
	// caught up, not a child without a console: a CREATE_NO_WINDOW process
	// has a birth console's host.
	deadline := time.Now().Add(birthHostPollWant)
	var hostPid uint32
	for {
		hosts, err := proc.ConsoleHostChildren(uint32(syscall.Getpid()))
		if err != nil {
			return err
		}
		if len(hosts) == 1 {
			hostPid = hosts[0]
			break
		}
		if len(hosts) > 1 {
			return fmt.Errorf("this process has %d console hosts (%v) where its own birth console can have one; "+
				"nothing measured against a walk this crowded would mean anything", len(hosts), hosts)
		}
		if time.Now().After(deadline) {
			return errors.New("a CREATE_NO_WINDOW process has a birth console's host; " +
				"the walk answering none is a walk that has not caught up")
		}
		time.Sleep(birthHostPollStep)
	}
	// CONTROL, and the one the old in-process test never took: the door the
	// shut is measured against must be open first.
	if !canOpenRaw(hostPid, processAllAccess) {
		return fmt.Errorf("the birth console's host (%d) already refuses this account everything, "+
			"so the shut below would be measuring nothing", hostPid)
	}
	// The guard's contract is pinned, not the console environment: the honest
	// answer for this child would also be one -- its own birth console, one
	// process attached -- but the injection is what keeps the guard's shape
	// the subject instead of the machine's console state.
	old := getConsoleProcessList
	getConsoleProcessList = func([]uint32) (int, error) { return 1, nil }
	defer func() { getConsoleProcessList = old }()
	account, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	if err := shutBirthConsoleHost(account); err != nil {
		return fmt.Errorf("the guard refused a console of this process's own that had exactly one host: %w", err)
	}
	if canOpenRaw(hostPid, processAllAccess) {
		return fmt.Errorf("the birth host the guard shut (%d) still opens for everything; the shut never landed", hostPid)
	}
	return nil
}
