package exec

import (
	"syscall"
	"testing"
	"unsafe"
)

// exec2 starts a command line exactly as the sandbox does, through
// CreateProcess, so the tests exercise the string wuserbox actually hands to
// Windows rather than a version Go re-quoted along the way.
func runLine(t *testing.T, commandLine string) error {
	t.Helper()
	var startup syscall.StartupInfo
	var created syscall.ProcessInformation
	startup.Cb = uint32(unsafe.Sizeof(startup))
	line, err := syscall.UTF16PtrFromString(commandLine)
	if err != nil {
		return err
	}
	if err := syscall.CreateProcess(nil, line, nil, nil, true, 0, nil, nil, &startup, &created); err != nil {
		return err
	}
	defer syscall.CloseHandle(created.Process)
	syscall.CloseHandle(created.Thread)
	if _, err := syscall.WaitForSingleObject(created.Process, 20000); err != nil {
		return err
	}
	return nil
}
