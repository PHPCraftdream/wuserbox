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
	return publish(path, listFor(value, entries), 0)
}

// SetWritable is Set for a permission that lets the sandbox change something,
// with a Low mandatory integrity label added in the same update.
//
// The label is what actually holds the boundary against deleting. DELETE and
// FILE_DELETE_CHILD are not part of a file's generic-write mapping, so the
// second, restricted access check a sandbox token gets never sees them, and
// the sandbox keeps the real user's own right to delete wherever their
// account already holds it — which, by Windows' own defaults, is everything
// in their home directory. Mandatory integrity is checked separately from the
// permissions and does cover those two, so a sandbox token running Low is
// refused them everywhere that is not labeled Low as well.
//
// That is also why this cannot be skipped quietly: the sandbox's own writes
// are refused the same way, so a permission handed over without the label is
// a permission that does not work. Writing the label needs a privilege an
// ordinary user's token does not carry, so a caller without it gets
// errNotLabeled back and can re-run the work with administrator rights.
//
// Both go in the one call that reaches the file system. Two calls would walk
// a directory that already holds files twice over, and the whole cost of
// handing a directory to a sandbox is that walk.
func SetWritable(path, account string, entries []ACE, inheritance uint32) error {
	if len(entries) == 0 {
		return fmt.Errorf("no access entries given for %s", path)
	}
	value, err := sid.Parse(account)
	if err != nil {
		return err
	}
	if !canLabel() {
		// The permission still goes on: refusing it outright would leave the
		// caller with nothing, and the caller is the one that knows whether it
		// can come back with the rights the label needs. What it must not do
		// is pretend the boundary is in force, so it is told.
		if err := publish(path, listFor(value, entries), 0); err != nil {
			return err
		}
		return ErrNotLabeled
	}
	label, err := lowIntegritySACL(inheritance)
	if err != nil {
		return err
	}
	return publish(path, listFor(value, entries), label)
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

// apply writes the finished list to the file system, together with the
// mandatory-label list when one was built for it.
func apply(path string, list []explicitAccess, sacl uintptr) error {
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

	info := uintptr(daclInfo)
	if sacl != 0 {
		info |= labelInfo
	}
	if r, _, _ := procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, info, 0, 0, updated, sacl); r != 0 {
		if r == 5 {
			if sacl != 0 {
				// The label is the part an ordinary token cannot write, so say
				// which of the two was refused rather than blaming ownership.
				return fmt.Errorf("labeling %s: %w", path, ErrNotLabeled)
			}
			return fmt.Errorf("changing the permissions of %s: access denied, you do not own it", path)
		}
		return fmt.Errorf("changing the permissions of %s: error %d", path, r)
	}
	return nil
}
