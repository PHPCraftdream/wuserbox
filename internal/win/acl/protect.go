package acl

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procStringToSecurityDescriptor = w32.Advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorDacl  = w32.Advapi32.NewProc("GetSecurityDescriptorDacl")
)

// Protect replaces the permissions of path with a fixed list that no sandbox
// can satisfy: the current user, the system and administrators. Inheritance is
// switched off, so a permission granted on a parent directory can never reach
// this object afterwards.
//
// A directory the sandbox may change still lets it delete children, whatever
// their own permissions say, so protected files are kept outside such
// directories.
func Protect(path string) error {
	user, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	inheritance := ""
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		inheritance = "OICI"
	}
	text := fmt.Sprintf("D:PAI(A;%s;GA;;;%s)(A;%s;GA;;;SY)(A;%s;GA;;;BA)",
		inheritance, user, inheritance, inheritance)

	var descriptor uintptr
	if r, _, err := procStringToSecurityDescriptor.Call(uintptr(unsafe.Pointer(w32.UTF16(text))), 1,
		uintptr(unsafe.Pointer(&descriptor)), 0); r == 0 {
		return fmt.Errorf("building protected permissions: %w", err)
	}
	defer w32.Free(descriptor)

	var present, defaulted int32
	var dacl uintptr
	if r, _, err := procGetSecurityDescriptorDacl.Call(descriptor, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return fmt.Errorf("reading protected permissions: %w", err)
	}
	const protectedDacl = 0x80000000
	if r, _, _ := procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo|protectedDacl, 0, 0, dacl, 0); r != 0 {
		return fmt.Errorf("protecting %s: error %d", path, r)
	}
	return nil
}
