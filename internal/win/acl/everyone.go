package acl

import (
	"fmt"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var procEqualSid = w32.Advapi32.NewProc("EqualSid")

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
// A list that cannot be read counts as not yet granted here, the opposite way
// round from writableBy and for the same reason: this decides whether a
// one-time step still has work to do, and doing it again is harmless while
// leaving it undone is not.
func Reads(path, account string) bool {
	held, err := heldBy(path, account, AccessReadExecute)
	return err == nil && held
}

// writableBy answers the question --audit is built on. A list that cannot be
// read counts as writable: the command exists to point at places worth looking
// at, and passing one over in silence is the one answer it must not give.
func writableBy(path, account string) bool {
	held, err := heldBy(path, account, changing)
	if err != nil {
		return true
	}
	return held
}

// heldBy reports whether account holds any of the wanted rights on path.
//
// Every entry counts, including the ones a directory above handed down. Asking
// only about an object's own entries -- which is all GetExplicitEntriesFromAcl
// answers with -- made --audit quiet about the ordinary case: one directory
// left open to Everyone, and everything under it open by inheritance with not
// one entry of its own to show for it. Measured: a subdirectory of a
// world-writable directory was reported as not writable by Everyone.
//
// A refusal settles it wherever one matches, because that is how Windows
// settles it: for a single token a matching refusal beats a matching
// permission whatever order the list is in.
func heldBy(path, account string, wanted uint32) (bool, error) {
	value, err := sid.Parse(account)
	if err != nil {
		return false, err
	}
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return false, fmt.Errorf("reading the permissions of %s: error %d", path, r)
	}
	defer w32.Free(descriptor)
	if dacl == nil {
		return true, nil // no permission list at all means everybody has everything
	}
	held, err := entriesOf(dacl)
	if err != nil {
		return false, fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	found := false
	for _, one := range held {
		const trusteeIsSID = 0
		if one.access.trustee.form != trusteeIsSID || one.access.permissions&wanted == 0 {
			continue
		}
		if !sameSID(one.access.trustee.name, value) {
			continue
		}
		if one.access.mode == denyAccess {
			return false, nil
		}
		if one.access.mode == grantAccess {
			found = true
		}
	}
	return found, nil
}
