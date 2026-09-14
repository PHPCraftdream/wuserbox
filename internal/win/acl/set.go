package acl

import (
	"fmt"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
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
	// setAccess replaces everything an account holds, refusals included.
	// Revoking does not: it removes permissions and leaves refusals behind,
	// and a refusal outlives the grant it was meant to accompany.
	setAccess    = 2
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

// publish is the step that writes a finished list to the file system. Tests
// replace it to count how often one call to Set reaches the disk.
var publish = apply

// Set replaces the entries for account with the ones given. All of them go in
// a single update, so one account can hold several entries that differ only in
// how they are inherited.
//
// The update is also the only one: nothing is written to the file system until
// the whole list is built. Clearing the account in its own update first would
// leave a moment with neither the old entries nor the new ones, and a directory
// held read-only inside a writable parent would be writable through inheritance
// for exactly as long as that moment lasts.
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
	return publish(path, listFor(value, entries), false)
}

// listFor builds the whole update for one account, in the order Windows
// applies it.
//
// The list opens by replacing everything the account holds, so stale entries
// cannot survive. It replaces rather than revokes: revoking takes away
// permissions and leaves refusals in place, so an account narrowed to
// read-only and then widened again would stay refused by an entry nobody
// asked to keep.
//
// Refusals come next and permissions last: Windows reads the finished list in
// order, and a refusal placed after a permission would never be reached.
func listFor(value uintptr, entries []ACE) []explicitAccess {
	list := []explicitAccess{entry(value, 0, InheritNone, setAccess)}
	for _, e := range entries {
		if e.Refuse {
			list = append(list, entry(value, e.Access, e.Inheritance, denyAccess))
		}
	}
	for _, e := range entries {
		if !e.Refuse {
			list = append(list, entry(value, e.Access, e.Inheritance, grantAccess))
		}
	}
	return list
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

// apply writes a finished list to the file system.
//
// whole says the list is the entire permission list of the object rather than
// a change to it: nothing is merged into what is already there, and the
// result is written as the object's own, so no directory above it hands
// anything down to it afterwards. Isolate needs that — merging would bring
// the inherited entries it just rewrote straight back, still inherited, and
// still handing out what they were rewritten to take away.
func apply(path string, list []explicitAccess, whole bool) error {
	const protectedDacl = 0x80000000
	information, current := uintptr(daclInfo), uintptr(0)
	if whole {
		information |= protectedDacl
	} else {
		var descriptor uintptr
		if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
			seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&current)), 0,
			uintptr(unsafe.Pointer(&descriptor))); r != 0 {
			return fmt.Errorf("reading the permissions of %s: error %d", path, r)
		}
		defer w32.Free(descriptor)
	}

	var updated uintptr
	if r, _, _ := procSetEntriesInAcl.Call(uintptr(len(list)), uintptr(unsafe.Pointer(&list[0])),
		current, uintptr(unsafe.Pointer(&updated))); r != 0 {
		return fmt.Errorf("building the permissions for %s: error %d", path, r)
	}
	defer w32.Free(updated)

	if r, _, _ := procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, information, 0, 0, updated, 0); r != 0 {
		if r == 5 {
			return fmt.Errorf("changing the permissions of %s: access denied, you do not own it", path)
		}
		return fmt.Errorf("changing the permissions of %s: error %d", path, r)
	}
	return nil
}
