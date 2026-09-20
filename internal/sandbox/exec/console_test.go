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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procGetStdHandle = w32.Kernel32.NewProc("GetStdHandle")
	procSetStdHandle = w32.Kernel32.NewProc("SetStdHandle")
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
	pumpRelay(relay, os.Stdout, os.Stdin)
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
	// pseudoconsole it was born attached to.
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
