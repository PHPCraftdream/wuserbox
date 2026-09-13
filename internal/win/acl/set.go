package acl

import (
	"fmt"
	"unsafe"

	"wuserbox/internal/win/sid"
	"wuserbox/internal/win/w32"
)

var (
	procGetNamedSecurityInfo = w32.Advapi32.NewProc("GetNamedSecurityInfoW")
	procSetNamedSecurityInfo = w32.Advapi32.NewProc("SetNamedSecurityInfoW")
	procSetEntriesInAcl      = w32.Advapi32.NewProc("SetEntriesInAclW")
)

const (
	seFileObject = 1
	daclInfo     = 4
	grantAccess  = 1
	denyAccess   = 3
	revokeAccess = 4
)

type trustee struct {
	multipleTrustee uintptr
	multipleOp      int32
	form            int32
	kind            int32
	name            uintptr
}

type explicitAccess struct {
	permissions uint32
	mode        int32
	inheritance uint32
	trustee     trustee
}

// Set replaces the entries for account with the ones given. All of them go in
// a single update, so one account can hold several entries that differ only in
// how they are inherited.
//
// Windows pushes inheritable entries down to existing children as well, so a
// permission set on a directory reaches the files already in it.
func Set(path, account string, entries []ACE) error {
	if len(entries) == 0 {
		return fmt.Errorf("no access entries given for %s", path)
	}
	value, err := sid.Parse(account)
	if err != nil {
		return err
	}
	// Start by clearing this account so stale entries cannot survive.
	list := []explicitAccess{entry(value, 0, InheritNone, revokeAccess)}
	for _, e := range entries {
		list = append(list, entry(value, e.Access, e.Inheritance, grantAccess))
	}
	return apply(path, list)
}

func entry(account uintptr, access, inheritance uint32, mode int32) explicitAccess {
	const trusteeIsSID, trusteeIsUnknown = 0, 5
	return explicitAccess{
		permissions: access,
		mode:        mode,
		inheritance: inheritance,
		trustee:     trustee{form: trusteeIsSID, kind: trusteeIsUnknown, name: account},
	}
}

func apply(path string, list []explicitAccess) error {
	var current, descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&current)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return fmt.Errorf("reading the permissions of %s: error %d", path, r)
	}
	defer w32.Free(descriptor)

	var updated uintptr
	if r, _, _ := procSetEntriesInAcl.Call(uintptr(len(list)), uintptr(unsafe.Pointer(&list[0])),
		current, uintptr(unsafe.Pointer(&updated))); r != 0 {
		return fmt.Errorf("building the permissions for %s: error %d", path, r)
	}
	defer w32.Free(updated)

	if r, _, _ := procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, updated, 0); r != 0 {
		if r == 5 {
			return fmt.Errorf("changing the permissions of %s: access denied, you do not own it", path)
		}
		return fmt.Errorf("changing the permissions of %s: error %d", path, r)
	}
	return nil
}
