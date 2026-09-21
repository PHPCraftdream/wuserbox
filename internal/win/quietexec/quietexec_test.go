package quietexec

// One observation, made structurally: a child started through Command holds
// a real console, and that console has no window. The parent first detaches
// from whatever console `go test` gave it -- without that, the child would
// quietly inherit it and the question would answer itself -- then starts a
// real child through Command, attaches to the child's console and asks that
// console for its window. The attachment is the proof the console exists;
// the zero handle is the proof nothing shows it.

import (
	"errors"
	"os/exec"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procFreeConsole      = w32.Kernel32.NewProc("FreeConsole")
	procAttachConsole    = w32.Kernel32.NewProc("AttachConsole")
	procGetConsoleWindow = w32.Kernel32.NewProc("GetConsoleWindow")
)

// TestCommandChildHoldsAWindowlessConsole proves by observation what
// Command promises: a console-subsystem child started by a caller with no
// console gets a real console -- AttachConsole to its pid succeeds, so it
// exists -- whose GetConsoleWindow answers 0. The window was never created;
// there is nothing to show and nothing to hide.
func TestCommandChildHoldsAWindowlessConsole(t *testing.T) {
	// Console state belongs to the whole process, so this test must run one
	// at a time: t.Parallel here would race the detach below against
	// whatever else in the package touches the console.
	//
	// FreeConsole drops the console `go test` gave this process. Its return
	// value is not read, on purpose: a process with no console at all -- a
	// headless CI runner, or the second run of this test in one binary
	// under -count -- fails FreeConsole legitimately. The only thing that
	// matters is that no console is left to inherit, and that is checked by
	// observation instead.
	procFreeConsole.Call()
	if hwnd, _, _ := procGetConsoleWindow.Call(); hwnd != 0 {
		t.Fatalf("FreeConsole left a console behind: GetConsoleWindow answered %#x", hwnd)
	}

	// A real child, alive long enough to observe: three seconds of ping.
	cmd := Command("cmd.exe", "/c", "ping", "-n", "3", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the child: %v", err)
	}

	// AttachConsole from the detached parent is the structural proof the
	// child HAS a console: nothing can attach to one that does not exist.
	// It can fail while conhost is still standing the console up during the
	// child's startup -- observed ERROR_INVALID_HANDLE on the first
	// attempt, succeeding about 200ms later -- so the call is retried
	// against a deadline, and the test fails only once the deadline passes,
	// never on the early attempts.
	attached := false
	deadline := time.Now().Add(30 * time.Second)
	for {
		if r, _, _ := procAttachConsole.Call(uintptr(cmd.Process.Pid)); r != 0 {
			attached = true
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !attached {
		t.Fatalf("AttachConsole to the child (pid %d) never succeeded within 30s", cmd.Process.Pid)
	}

	// The single observation the whole test exists for. Attached, so the
	// console being asked about is the child's: it must have no window.
	//
	// Deliberately nothing is asserted about foreground windows or
	// EnumWindows: a desk with a human on it changes foreground for reasons
	// of its own, and either check would add a flake on top of evidence
	// that is already stronger than both.
	if hwnd, _, _ := procGetConsoleWindow.Call(); hwnd != 0 {
		procFreeConsole.Call()
		t.Fatalf("the child's console has a window: GetConsoleWindow answered %#x", hwnd)
	}

	// FreeConsole again after the observation, so the parent is not holding
	// the child's console while it waits.
	procFreeConsole.Call()

	// There is deliberately no positive-control leg here -- no plain
	// exec.Command child launched to watch a window flash. That would put
	// the flash this package exists to remove back into every test run.
	// The contrast case is documented, not re-run.
	//
	// The child must exit successfully: ping -n 3 exits 0, and anything
	// else is reported with the code that arrived.
	err := cmd.Wait()
	if err == nil {
		return
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		t.Fatalf("the child ended with exit code %d, not 0: %v", exitErr.ExitCode(), err)
	}
	t.Fatalf("waiting for the child: %v", err)
}
