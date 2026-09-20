// The STARTUPINFOEX machinery for starting a child attached to a pseudo
// console (ConPTY) rather than to inherited standard handles -- the launch
// form Run cannot express, because Run always duplicates the caller's
// standard handles and points STARTF_USESTDHANDLES at the duplicates, which
// is the opposite of what a child born onto its own console wants.

package proc

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procInitProcThreadAttributeList   = w32.Kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute     = w32.Kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList = w32.Kernel32.NewProc("DeleteProcThreadAttributeList")
)

const (
	procThreadAttributePseudoConsole = 0x00020016 // PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
	extendedStartupInfoPresent       = 0x00080000 // EXTENDED_STARTUPINFO_PRESENT
)

// startupInfoEx mirrors STARTUPINFOEXW: a plain STARTUPINFOW followed by the
// attribute-list pointer CreateProcessAsUserW reads when
// EXTENDED_STARTUPINFO_PRESENT is set. Go's own syscall package has the same
// shape internally (_STARTUPINFOEXW, embedding StartupInfo), unexported and
// so not reusable here. The caller passes &ex.StartupInfo as the
// STARTUPINFO, with Cb sized to the whole struct.
type startupInfoEx struct {
	syscall.StartupInfo
	attributeList uintptr
}

// startupInfoForPseudoConsole builds a STARTUPINFOEX whose attribute list
// names pseudoConsole as the child's console, together with the cleanup to
// defer around the launch that uses it.
func startupInfoForPseudoConsole(pseudoConsole syscall.Handle) (*startupInfoEx, func(), error) {
	var size uintptr
	// Called with a null list, InitializeProcThreadAttributeList only
	// measures: it writes the buffer size a one-attribute list needs through
	// the fourth argument and fails on purpose, so the failure itself is not
	// worth reporting -- only a size it left at zero is.
	procInitProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return nil, nil, errors.New("sizing a thread attribute list")
	}
	buf := make([]byte, size)
	list := uintptr(unsafe.Pointer(&buf[0]))
	if r, _, callErr := procInitProcThreadAttributeList.Call(list, 1, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		return nil, nil, fmt.Errorf("initializing a thread attribute list: %w", callErr)
	}
	// list is a plain uintptr, invisible to the collector, so buf has to be
	// kept reachable through every use of list, all the way past the
	// CreateProcessAsUserW call that reads it -- the same reasoning
	// runAsAccount's own runtime.KeepAlive calls in logon.go exist for.
	// Keeping it here, inside the cleanup the caller defers around the
	// launch, holds buf alive until that cleanup runs, which is strictly
	// after the launch call is done with the list.
	freeStartup := func() {
		procDeleteProcThreadAttributeList.Call(list)
		runtime.KeepAlive(buf)
	}
	if r, _, callErr := procUpdateProcThreadAttribute.Call(list, 0, procThreadAttributePseudoConsole,
		uintptr(pseudoConsole), unsafe.Sizeof(pseudoConsole), 0, 0); r == 0 {
		freeStartup()
		return nil, nil, fmt.Errorf("naming the pseudo console in the thread attribute list: %w", callErr)
	}
	startup := &startupInfoEx{attributeList: list}
	startup.Cb = uint32(unsafe.Sizeof(*startup))
	return startup, freeStartup, nil
}
