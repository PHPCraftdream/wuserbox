package token

import (
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procLookupPrivilegeValue = w32.Advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivilege = w32.Advapi32.NewProc("AdjustTokenPrivileges")
)

// securityPrivilege is what writing a mandatory integrity label needs. An
// administrator's token carries it switched off; an ordinary user's token
// does not carry it at all, and nothing can add it to a token that already
// exists — the list is fixed when the token is made, at logon.
const securityPrivilege = "SeSecurityPrivilege"

type luid struct {
	low  uint32
	high int32
}

type luidAndAttributes struct {
	value      luid
	attributes uint32
}

type tokenPrivileges struct {
	count      uint32
	privileges [1]luidAndAttributes
}

// CanLabel switches on the privilege that writing an integrity label needs,
// and says whether this process has it to switch on.
//
// It is asked rather than assumed: the answer is yes in the elevated copy
// wuserbox re-runs itself as, and no in the ordinary one, which is exactly
// the difference that decides whether a grant can be finished here or has to
// be handed to an elevated run.
func CanLabel() bool {
	var self syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)),
		syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY, &self); err != nil {
		return false
	}
	defer self.Close()

	name, err := syscall.UTF16PtrFromString(securityPrivilege)
	if err != nil {
		return false
	}
	var value luid
	if r, _, _ := procLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&value))); r == 0 {
		return false
	}
	const enabled = 0x00000002 // SE_PRIVILEGE_ENABLED
	wanted := tokenPrivileges{count: 1}
	wanted.privileges[0] = luidAndAttributes{value: value, attributes: enabled}

	// AdjustTokenPrivileges reports success even when it changed nothing,
	// leaving the real answer in the last error. A token without the privilege
	// in its list is the ordinary case here, not a failure to report.
	r, _, callErr := procAdjustTokenPrivilege.Call(uintptr(self), 0,
		uintptr(unsafe.Pointer(&wanted)), 0, 0, 0)
	if r == 0 {
		return false
	}
	const notAllAssigned = syscall.Errno(1300) // ERROR_NOT_ALL_ASSIGNED
	return callErr != notAllAssigned
}
