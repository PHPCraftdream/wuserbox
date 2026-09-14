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
// can change or delete: full control for the current user, the system and
// administrators, and reading for everyone else. Inheritance is switched
// off, so a permission granted on a parent directory can never reach this
// object afterwards.
//
// Reading is not part of what this refuses. A sandbox's restricted list
// checks every access now, not only writes, so a file whose entries named
// only the owner, system and administrators would have gone unreadable to
// every sandbox along with unwritable -- Everyone and BUILTIN\Users, which
// every restricted list carries, are given read access here for the same
// reason grant.Apply never takes reading away when it narrows either of
// them elsewhere.
func Protect(path string) error {
	user, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	inheritance := ""
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		inheritance = "OICI"
	}
	text := fmt.Sprintf("D:PAI(A;%s;GA;;;%s)(A;%s;GA;;;SY)(A;%s;GA;;;BA)(A;%s;0x%x;;;%s)(A;%s;0x%x;;;%s)",
		inheritance, user, inheritance, inheritance,
		inheritance, AccessReadExecute, sid.Everyone,
		inheritance, AccessReadExecute, sid.Users)

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
