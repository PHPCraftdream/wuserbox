// Taking a console of one's own, for a program that refuses to speak through
// anything else.
//
// The bridge pipes carry bytes, and bytes are all a line-oriented program
// needs; a raw-mode terminal program checks whether its standard input is a
// real console before it will start at all, and a pipe is never one. The
// account cannot attach to the console wuserbox was started from --
// AttachConsole(ATTACH_PARENT_PROCESS) answers "access is denied", measured
// against a real sandbox account -- but it can make a console of its own:
// AllocConsole succeeds and creates a working one, GetConsoleMode and all.
// What it gets is a new, separate console window, not a share of the
// caller's, and that tradeoff is the shape of the fix rather than a
// limitation to apologize for.
//
// The relay in this file is the second answer to the same problem: a pseudo
// console, which is a console with no window at all, hosted by a conhost of
// this account's own, whose rendered bytes and keystrokes cross this process
// as plain pipe bytes -- the shape
// docs/investigations/2026-09-20-same-window-console.md measured end to end
// under a real sandbox token.

package exec

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procFreeConsole          = w32.Kernel32.NewProc("FreeConsole")
	procAllocConsole         = w32.Kernel32.NewProc("AllocConsole")
	procCreatePseudoConsole  = w32.Kernel32.NewProc("CreatePseudoConsole")
	procClosePseudoConsole   = w32.Kernel32.NewProc("ClosePseudoConsole")
	procSetHandleInformation = w32.Kernel32.NewProc("SetHandleInformation")
)

// takeOwnConsole gives this process a console of its own and points its
// standard streams at it, so the program started next inherits real console
// handles through the same STARTUPINFO duplication proc.Run already uses.
//
// The stub is born with a console attached -- CREATE_NO_WINDOW creates one
// without putting a window on it -- and AllocConsole refuses while any
// console is attached, so FreeConsole goes first. Its error is ignored on
// purpose: whatever is wrong at that point, AllocConsole fails right after
// with a reason of its own, and that is the one worth reporting.
//
// GetStdHandle is never repointed at a console AllocConsole has just made --
// the same CRT-startup gap internal/win/proc/stdin_bridge_test.go's
// fixupStdinFromConin documents -- so the console devices are opened by
// name, and a GetConsoleMode answer on each is the check that what was
// opened really is the new console rather than a failure holding a handle.
//
// The returned func puts the previous streams back. os.Exit skips deferred
// calls, so on the success path it never runs; on the error path it hands
// the streams back to the bridge pipes that reach the caller's terminal,
// where an error can actually be read.
func takeOwnConsole() (func(), error) {
	procFreeConsole.Call()
	if r, _, callErr := procAllocConsole.Call(); r == 0 {
		return nil, fmt.Errorf("allocating a console of its own: %w", callErr)
	}
	oldStdin, oldStdout, oldStderr := os.Stdin, os.Stdout, os.Stderr
	if err := openConsoleStreams(); err != nil {
		os.Stdin, os.Stdout, os.Stderr = oldStdin, oldStdout, oldStderr
		return nil, err
	}
	// The closure is also what keeps the old *os.File values reachable until
	// the stub is done with them: a bridge writer the collector closed early
	// would end the caller's relay before the stub's last words reached it.
	return func() { os.Stdin, os.Stdout, os.Stderr = oldStdin, oldStdout, oldStderr }, nil
}

// openConsoleStreams opens CONIN$ once for input and CONOUT$ twice for
// output and error, and installs them as this process's standard streams.
// Two CONOUT$ opens rather than one handle shared between them, so that a
// program closing one of its output streams does not take the other with
// it; the C runtime's own fallback, which opens CONIN$/CONOUT$/CONERR$
// after a console it did not recognize, is the shape being copied.
func openConsoleStreams() error {
	conin, err := openConsoleDevice("CONIN$")
	if err != nil {
		return err
	}
	conout, err := openConsoleDevice("CONOUT$")
	if err != nil {
		_ = conin.Close()
		return err
	}
	conerr, err := openConsoleDevice("CONOUT$")
	if err != nil {
		_ = conin.Close()
		_ = conout.Close()
		return err
	}
	os.Stdin, os.Stdout, os.Stderr = conin, conout, conerr
	return nil
}

// openConsoleDevice opens one console device and proves it is one: a
// GetConsoleMode that answers is the difference between the new console and
// a stale handle to a console this process is no longer attached to.
func openConsoleDevice(name string) (*os.File, error) {
	device, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(device,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", name, err)
	}
	file := os.NewFile(uintptr(handle), name)
	var mode uint32
	if err := syscall.GetConsoleMode(handle, &mode); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a console: %w", name, err)
	}
	return file, nil
}

// handleFlagInherit is HANDLE_FLAG_INHERIT, the one flag noInherit is
// called for below.
const handleFlagInherit = 0x00000001

// consoleRelay is a pseudo console taken for the program, with the two pipe
// ends that carry it. Bytes written to input are the console's keystrokes;
// bytes read from output are the console's rendered output, VT and all --
// the same stream a real terminal's pixels start life as. hpc is the
// console itself, named in the child's thread attribute list by
// proc.RunWithConsole.
type consoleRelay struct {
	hpc    syscall.Handle
	input  *os.File
	output *os.File
}

// takeConsoleRelay gives the program a console that has no window at all: a
// pseudo console, hosted by a conhost of this account's own. Unlike
// takeOwnConsole it changes nothing about this process's own standard
// streams -- the stub keeps the bridge pipes it was born with -- because the
// console is not for this process: it exists to be attached to the program
// through proc.RunWithConsole and relayed as bytes.
//
// It is called from the same pre-Shield window as takeOwnConsole, for the
// same measured reason: the console's conhost is born under the account's
// unrestricted token, and CreatePseudoConsole under the token narrowed by
// Shield is a refusal nobody has had to measure to predict. What was
// measured, docs/investigations/2026-09-20-same-window-console.md section 4,
// is the rest of it: it succeeds under the real account token, and a child
// attaches through the exact call proc.RunWithConsole makes.
//
// CreatePseudoConsole takes one input handle and one output handle and
// duplicates what it needs, so this process's own copies of those two ends
// are closed the moment the call returns -- keeping them open would be
// exactly the ambient-inheritance gap
// docs/reviews/sandbox-security-review-2026-09-19.md's P2-1 is about. The
// kept ends are stripped of HANDLE_FLAG_INHERIT for the same reason.
//
// The console is born 80 columns by 25 rows and nothing resizes it yet; that,
// the relay across the operator bridge, and interrupt forwarding are later
// work, not oversights here.
func takeConsoleRelay() (*consoleRelay, error) {
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("creating the relay's input pipe: %w", err)
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		_ = inRead.Close()
		_ = inWrite.Close()
		return nil, fmt.Errorf("creating the relay's output pipe: %w", err)
	}
	var hpc syscall.Handle
	// COORD{X: 80, Y: 25} packed into the single register the x64 calling
	// convention uses for a struct this size -- X in the low 16 bits, Y in
	// the next 16.
	const width, height = 80, 25
	size := uintptr(uint32(uint16(width)) | uint32(uint16(height))<<16)
	r, _, _ := procCreatePseudoConsole.Call(size, inRead.Fd(), outWrite.Fd(), 0, uintptr(unsafe.Pointer(&hpc)))
	// CreatePseudoConsole duplicates what it needs; this process's own
	// copies of the two ends are surplus the moment the call returns, kept
	// open or not.
	inRead.Close()
	outWrite.Close()
	if r != 0 {
		_ = inWrite.Close()
		_ = outRead.Close()
		// An HRESULT is CreatePseudoConsole's own result and the whole of
		// what it reports: unlike the BOOL-style calls elsewhere here there
		// is no error code behind it worth reaching for.
		return nil, fmt.Errorf("creating a pseudo console: hresult 0x%x", r)
	}
	relay := &consoleRelay{hpc: hpc, input: inWrite, output: outRead}
	if err := noInherit(relay.input); err != nil {
		relay.close()
		return nil, fmt.Errorf("excluding the relay's input end from inheritance: %w", err)
	}
	if err := noInherit(relay.output); err != nil {
		relay.close()
		return nil, fmt.Errorf("excluding the relay's output end from inheritance: %w", err)
	}
	return relay, nil
}

// noInherit strips HANDLE_FLAG_INHERIT from file's underlying handle -- the
// same hygiene logon.go's noInherit applies to the ends of the bridge pipes
// that stay behind: both kept relay ends stay in this process, and ambient
// inheritance is how a handle meant to stay here reaches a child it was
// never meant for.
func noInherit(file *os.File) error {
	if r, _, callErr := procSetHandleInformation.Call(file.Fd(), handleFlagInherit, 0); r == 0 {
		return callErr
	}
	return nil
}

// close ends the pseudo console and both pipe ends. Closing the console is
// also what ends its conhost and what lets a reader of output reach EOF --
// the measured shape of every drain in this repository that reads a pseudo
// console's pipe. os.Exit skips deferred calls, so on the stub's success
// path close never runs; the stub's own death closes everything it names.
// Safe to call twice: the handle is cleared before it is closed, which is
// what lets a test close the relay explicitly and still have its deferred
// call find nothing left to do.
func (r *consoleRelay) close() {
	if r == nil {
		return
	}
	if r.hpc != 0 {
		procClosePseudoConsole.Call(uintptr(r.hpc))
		r.hpc = 0
	}
	_ = r.input.Close()
	_ = r.output.Close()
}

// pumpRelay starts the two copy loops that carry the relayed console
// across this process's own standard streams -- the bridge pipes the
// run's caller duplicated its console into at this stub's birth. Rendered
// VT read from the relay's output goes out as this process writes it, and
// whatever the caller forwarded in is written to the relay's input as it
// arrives; neither loop translates, because both ends already hold the
// bytes a terminal would have sent or drawn. Nothing here waits for them:
// they run until this process ends, which is the same moment the
// program's exit makes the run move on, and the streams they name close
// with it.
func pumpRelay(relay *consoleRelay, stdout io.Writer, stdin io.Reader) {
	go func() {
		_, _ = io.Copy(stdout, relay.output)
	}()
	go func() {
		_, _ = io.Copy(relay.input, stdin)
	}()
}
