package proc

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var procShellExecuteEx = w32.Shell32.NewProc("ShellExecuteExW")

type executeInfo struct {
	size       uint32
	mask       uint32
	window     uintptr
	verb       *uint16
	file       *uint16
	parameters *uint16
	directory  *uint16
	show       int32
	instance   uintptr
	idList     uintptr
	class      *uint16
	classKey   uintptr
	hotKey     uint32
	icon       uintptr
	process    syscall.Handle
}

// showNormal makes the elevated child's console appear like any other
// window, instead of ShellExecuteEx's zero value for show, SW_HIDE.
//
// The elevated child is where stderr with the real cause of a failed --init
// or --rm lands: the parent that asked for elevation only ever learns the
// exit code (see prepare.go), not what was written to the console. A hidden
// window means that detail is gone the moment the child exits -- measured
// live, as a bare "failed with exit code 1" with no way to recover why. The
// elevation itself is already announced to the user before this runs, so a
// few seconds of visible console during it is not a new surprise.
const showNormal = 1

// Elevate re-runs this executable with administrator rights, waits for it and
// returns its exit code. The user sees a consent prompt.
func Elevate(args []string) (int, error) {
	executable, err := os.Executable()
	if err != nil {
		return -1, err
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	directory, _ := os.Getwd()

	const keepProcessHandle = 0x40
	info := executeInfo{
		mask:       keepProcessHandle,
		verb:       w32.UTF16("runas"),
		file:       w32.UTF16(executable),
		parameters: w32.UTF16(strings.Join(quoted, " ")),
		directory:  w32.UTF16(directory),
		show:       showNormal,
	}
	info.size = uint32(unsafe.Sizeof(info))
	if r, _, callErr := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return -1, fmt.Errorf("elevation was refused: %w", callErr)
	}
	defer syscall.CloseHandle(info.process)
	if _, err := syscall.WaitForSingleObject(info.process, syscall.INFINITE); err != nil {
		return -1, err
	}
	var code uint32
	procGetExitCode.Call(uintptr(info.process), uintptr(unsafe.Pointer(&code)))
	return int(code), nil
}
