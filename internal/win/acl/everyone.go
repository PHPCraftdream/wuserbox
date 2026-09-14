package acl

import (
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procGetExplicitEntries = w32.Advapi32.NewProc("GetExplicitEntriesFromAclW")
	procEqualSid           = w32.Advapi32.NewProc("EqualSid")
)

// EveryoneWritable reports whether Everyone may write to path. Such places
// stay writable inside a sandbox, because Everyone is one of the identifiers
// the sandbox token is restricted to.
func EveryoneWritable(path string) bool {
	return writableBy(path, sid.Everyone)
}

// UsersWritable reports whether BUILTIN\Users may write to path, the same
// concern as EveryoneWritable for the other identifier every sandbox's
// restricted list has to carry. Some machines grant Users write access to
// shared system directories -- C:\ProgramData is a common one -- by Windows'
// own default, not through anything wuserbox did.
func UsersWritable(path string) bool {
	return writableBy(path, sid.Users)
}

// Reads reports whether account already holds read access on path. It is how
// a one-time provisioning step can ask the file system whether it ever
// finished, instead of trusting a marker written beside it.
func Reads(path, account string) bool {
	return heldBy(path, account, AccessReadExecute)
}

func writableBy(path, account string) bool {
	return heldBy(path, account, writeMask)
}

func heldBy(path, account string, wanted uint32) bool {
	value, err := sid.Parse(account)
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
		if e.mode != grantAccess || e.trustee.form != trusteeIsSID || e.permissions&wanted == 0 {
			continue
		}
		if same, _, _ := procEqualSid.Call(e.trustee.name, value); same != 0 {
			return true
		}
	}
	return false
}
