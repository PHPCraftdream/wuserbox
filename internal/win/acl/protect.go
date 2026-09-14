package acl

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procStringToSecurityDescriptor = w32.Advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorDacl  = w32.Advapi32.NewProc("GetSecurityDescriptorDacl")
)

// Protect replaces the permissions of path with a fixed list that no sandbox
// can change or delete: full control for the current user, the system and
// administrators, and reading for the group every sandbox's restricted list
// carries. Inheritance is switched off, so a permission granted on a parent
// directory can never reach this object afterwards.
//
// Reading is not part of what this refuses, and the identifier it is given to
// is the whole of the care here. A sandbox's restricted list checks every
// access now, not only writes, so a file naming only the owner, the system
// and administrators goes unreadable to every sandbox along with unwritable.
// Everyone and BUILTIN\Users would fix that and give it away: this is applied
// to .ssh, .aws, .netrc and the rest of them, so on a machine with a second
// local account it would hand that account the owner's private keys.
// group.ReadGroup has no members at all, so no ordinary token carries it and
// no other account gains anything, while a sandbox — which carries it among
// its restricting identifiers rather than its groups — passes its second
// check on it and still has to pass the first as the user it really is.
//
// Where that group does not exist yet, nothing takes its place. A protected
// file the sandbox cannot read is the safe half of that choice.
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
	if reader, err := sid.Lookup(group.ReadGroup); err == nil {
		text += fmt.Sprintf("(A;%s;0x%x;;;%s)", inheritance, AccessReadExecute, reader.String())
	}

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
