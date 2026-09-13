// Package proc starts processes: sandboxed in the current console, or
// elevated through a consent prompt.
package proc

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"wuserbox/internal/win/w32"
)

var (
	procCreateProcessAsUser = w32.Advapi32.NewProc("CreateProcessAsUserW")
	procGetExitCode         = w32.Kernel32.NewProc("GetExitCodeProcess")
)

// Run starts a command under the given token in the caller's console, waits
// for it and returns its exit code. Standard handles are inherited, so the
// child shares the terminal.
func Run(token syscall.Token, commandLine, directory string) (int, error) {
	var startup syscall.StartupInfo
	var created syscall.ProcessInformation
	startup.Cb = uint32(unsafe.Sizeof(startup))
	line, err := syscall.UTF16FromString(commandLine)
	if err != nil {
		return -1, err
	}
	r, _, callErr := procCreateProcessAsUser.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&line[0])),
		0, 0, 1, 0, 0, uintptr(unsafe.Pointer(w32.UTF16(directory))),
		uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&created)))
	if r == 0 {
		return -1, fmt.Errorf("starting %s: %v", commandLine, callErr)
	}
	syscall.CloseHandle(created.Thread)
	defer syscall.CloseHandle(created.Process)

	// Ctrl+C reaches the child directly through the shared console; this
	// process must outlive it to report the exit code.
	signal.Ignore(os.Interrupt)
	if _, err := syscall.WaitForSingleObject(created.Process, syscall.INFINITE); err != nil {
		return -1, err
	}
	var code uint32
	procGetExitCode.Call(uintptr(created.Process), uintptr(unsafe.Pointer(&code)))
	return int(code), nil
}
