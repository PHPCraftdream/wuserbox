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

package exec

import (
	"fmt"
	"os"
	"syscall"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procFreeConsole  = w32.Kernel32.NewProc("FreeConsole")
	procAllocConsole = w32.Kernel32.NewProc("AllocConsole")
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
