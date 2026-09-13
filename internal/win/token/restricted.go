// Package token builds the restricted access token a sandbox runs under.
package token

import (
	"fmt"
	"syscall"
	"unsafe"

	"wuserbox/internal/win/sid"
	"wuserbox/internal/win/w32"
)

var (
	procCreateRestrictedToken      = w32.Advapi32.NewProc("CreateRestrictedToken")
	procSetTokenInformation        = w32.Advapi32.NewProc("SetTokenInformation")
	procStringToSecurityDescriptor = w32.Advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorDacl  = w32.Advapi32.NewProc("GetSecurityDescriptorDacl")
)

const (
	classLogonSid       = 28
	classDefaultDacl    = 6
	disableMaxPrivilege = 0x1
	writeRestricted     = 0x8
)

type sidAndAttributes struct {
	sid        uintptr
	attributes uint32
}

// Restricted derives a write-restricted token from the caller's own token.
// Reads keep the caller's rights. Every write is checked a second time against
// the restricting identifiers, so it succeeds only where the sandbox group has
// a permission of its own.
func Restricted(group string) (syscall.Token, error) {
	var self syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &self); err != nil {
		return 0, fmt.Errorf("opening the process token: %v", err)
	}
	defer self.Close()

	userBuf, err := information(self, syscall.TokenUser)
	if err != nil {
		return 0, err
	}
	logonBuf, err := information(self, classLogonSid)
	if err != nil {
		return 0, err
	}
	user := *(*uintptr)(unsafe.Pointer(&userBuf[0]))
	// TOKEN_GROUPS: a count and padding, then the first entry's identifier.
	logon := *(*uintptr)(unsafe.Pointer(&logonBuf[unsafe.Sizeof(uintptr(0))]))

	groupSID, err := sid.Parse(group)
	if err != nil {
		return 0, err
	}
	everyone, err := sid.Parse(sid.Everyone)
	if err != nil {
		return 0, err
	}
	restricting := []sidAndAttributes{{groupSID, 0}, {everyone, 0}, {logon, 0}}

	var restricted syscall.Token
	r, _, callErr := procCreateRestrictedToken.Call(uintptr(self), writeRestricted|disableMaxPrivilege,
		0, 0, 0, 0, uintptr(len(restricting)), uintptr(unsafe.Pointer(&restricting[0])),
		uintptr(unsafe.Pointer(&restricted)))
	if r == 0 {
		return 0, fmt.Errorf("creating the restricted token: %v", callErr)
	}
	if err := shareWithGroup(restricted, formatSID(user), group); err != nil {
		return 0, err
	}
	return restricted, nil
}

func information(token syscall.Token, class uint32) ([]byte, error) {
	var size uint32
	syscall.GetTokenInformation(token, class, nil, 0, &size)
	buf := make([]byte, size)
	if err := syscall.GetTokenInformation(token, class, &buf[0], size, &size); err != nil {
		return nil, fmt.Errorf("reading token information %d: %v", class, err)
	}
	return buf, nil
}

func formatSID(pointer uintptr) string {
	var text *uint16
	proc := w32.Advapi32.NewProc("ConvertSidToStringSidW")
	if r, _, _ := proc.Call(pointer, uintptr(unsafe.Pointer(&text))); r == 0 {
		return ""
	}
	defer w32.Free(uintptr(unsafe.Pointer(text)))
	return w32.GoString(text)
}

// shareWithGroup makes objects the sandbox creates reachable by other
// processes of the same sandbox: their default permissions name the group,
// which is what the second access check needs.
func shareWithGroup(token syscall.Token, user, group string) error {
	text := fmt.Sprintf("D:(A;;GA;;;%s)(A;;GA;;;%s)(A;;GA;;;%s)", user, sid.System, group)
	var descriptor uintptr
	if r, _, err := procStringToSecurityDescriptor.Call(uintptr(unsafe.Pointer(w32.UTF16(text))), 1,
		uintptr(unsafe.Pointer(&descriptor)), 0); r == 0 {
		return fmt.Errorf("building the default permissions: %v", err)
	}
	defer w32.Free(descriptor)

	var present, defaulted int32
	var dacl uintptr
	if r, _, err := procGetSecurityDescriptorDacl.Call(descriptor, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return fmt.Errorf("reading the default permissions: %v", err)
	}
	if r, _, err := procSetTokenInformation.Call(uintptr(token), classDefaultDacl,
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Sizeof(dacl))); r == 0 {
		return fmt.Errorf("setting the default permissions: %v", err)
	}
	return nil
}
