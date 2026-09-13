package acl

import (
	"unsafe"

	"wuserbox/internal/win/sid"
	"wuserbox/internal/win/w32"
)

var (
	procGetExplicitEntries = w32.Advapi32.NewProc("GetExplicitEntriesFromAclW")
	procEqualSid           = w32.Advapi32.NewProc("EqualSid")
)

// EveryoneWritable reports whether Everyone may write to path. Such places
// stay writable inside a sandbox, because Everyone is one of the identifiers
// the sandbox token is restricted to.
func EveryoneWritable(path string) bool {
	everyone, err := sid.Parse(sid.Everyone)
	if err != nil {
		return false
	}
	var dacl, descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return false
	}
	defer w32.Free(descriptor)
	if dacl == 0 {
		return true // no permission list at all means everyone has full access
	}
	var count uint32
	var entries *explicitAccess
	if r, _, _ := procGetExplicitEntries.Call(dacl, uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&entries))); r != 0 {
		return false
	}
	defer w32.Free(uintptr(unsafe.Pointer(entries)))
	for _, e := range unsafe.Slice(entries, count) {
		const trusteeIsSID = 0
		if e.mode != grantAccess || e.trustee.form != trusteeIsSID || e.permissions&writeMask == 0 {
			continue
		}
		if same, _, _ := procEqualSid.Call(e.trustee.name, everyone); same != 0 {
			return true
		}
	}
	return false
}
