// Package proc starts processes: sandboxed in the current console, or
// elevated through a consent prompt.
package proc

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procCreateProcessAsUser = w32.Advapi32.NewProc("CreateProcessAsUserW")
	procGetExitCode         = w32.Kernel32.NewProc("GetExitCodeProcess")
)

// Run starts a command under the given token in the caller's console, waits
// for it and returns its exit code. Standard handles are inherited, so the
// child shares the terminal.
//
// The child is put in a job object with kill-on-close before it is allowed
// to run, so nothing it starts outlives it and nothing survives wuserbox
// being killed outright. What the job does not do is take Ctrl+C away from
// the child: a keypress still reaches it through the console, because for
// most of what runs here -- an agent interrupting the turn it is in the
// middle of, a shell clearing its line, a REPL -- Ctrl+C is the program's own
// business and not a request to end the run. Insisting is what ends it; see
// waitOrStop.
func Run(token syscall.Token, commandLine, directory string) (int, error) {
	j, err := newJob()
	if err != nil {
		return -1, err
	}
	defer j.Close()

	var startup syscall.StartupInfo
	var created syscall.ProcessInformation
	startup.Cb = uint32(unsafe.Sizeof(startup))
	line, err := syscall.UTF16FromString(commandLine)
	if err != nil {
		return -1, err
	}
	// Suspended only, so that nothing it starts can slip out before it is
	// assigned to the job. Deliberately not in a process group of its own:
	// that would disable Ctrl+C for it entirely, and the point is to leave the
	// keypress with the program.
	const flags = createSuspended
	r, _, callErr := procCreateProcessAsUser.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&line[0])),
		0, 0, 1, flags, 0, uintptr(unsafe.Pointer(w32.UTF16(directory))),
		uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&created)))
	if r == 0 {
		return -1, fmt.Errorf("starting %s: %w", commandLine, callErr)
	}
	defer syscall.CloseHandle(created.Process)
	defer syscall.CloseHandle(created.Thread)

	if err := j.assign(created.Process); err != nil {
		procTerminateProcess.Call(uintptr(created.Process), 1)
		return -1, err
	}
	procResumeThread.Call(uintptr(created.Thread))

	return j.waitOrStop(created.Process)
}
