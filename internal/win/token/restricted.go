// Package token builds the restricted access token a sandbox runs under.
package token

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
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
)

type sidAndAttributes struct {
	sid        uintptr
	attributes uint32
}

// Restricted derives a fully restricted token from the caller's own token.
// Every access, not only writes, is checked a second time against the
// restricting identifiers, so it succeeds only where the sandbox group — or
// one of the shared identifiers alongside it — has a permission of its own.
// That is what closes deleting outside the sandbox and deleting a peer
// sandbox's files: DELETE and FILE_DELETE_CHILD go through the same check as
// everything else here, unlike the generic-write mapping a write-restricted
// token uses.
//
// Everyone and BUILTIN\Users are restricting identifiers too, not only the
// sandbox's own group: starting any program that loads the window subsystem
// needs Everyone, and reading System32 or Program Files needs Users, since
// those grant Users read and execute rather than Everyone. Granting a
// directory to one sandbox therefore has to take Everyone's and Users' write
// access away on that same directory wherever it is granted — grant.Apply
// does that — or every other sandbox holding either identifier could reach
// it too.
func Restricted(sandboxGroup string) (syscall.Token, error) {
	var self syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &self); err != nil {
		return 0, fmt.Errorf("opening the process token: %w", err)
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

	groupSID, err := sid.Parse(sandboxGroup)
	if err != nil {
		return 0, err
	}
	everyone, err := sid.Parse(sid.Everyone)
	if err != nil {
		return 0, err
	}
	users, err := sid.Parse(sid.Users)
	if err != nil {
		return 0, err
	}
	restricting := []sidAndAttributes{{groupSID, 0}, {everyone, 0}, {users, 0}, {logon, 0}}
	// A sandbox built before ReadGroup existed simply runs without it: the
	// profile reads that depended on it fail, the same way any other missing
	// grant would, rather than refusing to run at all.
	if read, err := sid.Lookup(group.ReadGroup); err == nil {
		restricting = append(restricting, sidAndAttributes{uintptr(unsafe.Pointer(&read[0])), 0})
	}

	var restricted syscall.Token
	r, _, callErr := procCreateRestrictedToken.Call(uintptr(self), disableMaxPrivilege,
		0, 0, 0, 0, uintptr(len(restricting)), uintptr(unsafe.Pointer(&restricting[0])),
		uintptr(unsafe.Pointer(&restricted)))
	if r == 0 {
		return 0, fmt.Errorf("creating the restricted token: %w", callErr)
	}
	if err := shareWithGroup(restricted, formatSID(user), sandboxGroup); err != nil {
		return 0, err
	}
	return restricted, nil
}

func information(token syscall.Token, class uint32) ([]byte, error) {
	var size uint32
	syscall.GetTokenInformation(token, class, nil, 0, &size)
	buf := make([]byte, size)
	if err := syscall.GetTokenInformation(token, class, &buf[0], size, &size); err != nil {
		return nil, fmt.Errorf("reading token information %d: %w", class, err)
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
		return fmt.Errorf("building the default permissions: %w", err)
	}
	defer w32.Free(descriptor)

	var present, defaulted int32
	var dacl uintptr
	if r, _, err := procGetSecurityDescriptorDacl.Call(descriptor, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return fmt.Errorf("reading the default permissions: %w", err)
	}
	if r, _, err := procSetTokenInformation.Call(uintptr(token), classDefaultDacl,
		uintptr(unsafe.Pointer(&dacl)), unsafe.Sizeof(dacl)); r == 0 {
		return fmt.Errorf("setting the default permissions: %w", err)
	}
	return nil
}
