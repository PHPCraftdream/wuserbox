package acl

import (
	"fmt"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var procGetAce = w32.Advapi32.NewProc("GetAce")

// aclHeader and aceHeader are what Windows puts in front of a permission list
// and of each entry in it. They are read through typed pointers rather than by
// address arithmetic, so that nothing has to turn a plain number back into a
// pointer: this memory belongs to Windows rather than to Go, and the compiler
// is right to want that said carefully.
type (
	aclHeader struct {
		revision byte
		_        byte
		size     uint16
		count    uint16
		_        uint16
	}
	aceHeader struct {
		kind  byte
		flags byte
		size  uint16
		mask  uint32
	}
)

// Isolate hands account the access described by entries, and pins the whole
// permission list of path while doing it, so that nothing above can let
// anybody else write to what is inside.
//
// The sandbox's own token is fully restricted, checked against every access
// rather than only writes, which is what makes deleting answer to the
// sandbox's own identifier instead of the caller's account. Everyone and
// BUILTIN\Users have to sit in that restricted list too, or the sandbox could
// not read the system it needs to run anything — so any directory whose
// permissions let either of them write is writable by every sandbox equally,
// whichever one this call is for. Their write access has to go.
//
// Three things make that harder than replacing two entries:
//
// A refusal cannot do it. The sandbox this grant is for belongs to Everyone
// and Users as well, so a refusal aimed at either would refuse this same
// sandbox its own directory. Windows honors a matching refusal over a
// matching permission for one token whatever order the list is in — measured
// directly, holding even for a hand-built list where the permission for the
// sandbox's own identifier came first.
//
// Replacing what those two hold is not enough either, because an entry handed
// down from a directory above is a copy that lives in that parent, and
// rewriting this object's list does not touch it. Windows then adds up every
// entry that matches: a granted directory would carry a read-only entry of
// ours and an inherited writable one from its parent, and the writable one
// would win the part it covers. So the list is rebuilt from what the object
// effectively has, inherited entries included, and written back as the
// object's own — after which no parent can hand anything down here again.
//
// Narrowing is only ever narrowing. An entry those two never had is not
// added: handing Everyone read access to a directory it could not read before
// would widen what every other account on the machine can see, which is the
// opposite of the point.
func Isolate(path, account string, entries []ACE, reach uint32) error {
	value, err := sid.Parse(account)
	if err != nil {
		return err
	}
	everyone, err := sid.Parse(sid.Everyone)
	if err != nil {
		return err
	}
	users, err := sid.Parse(sid.Users)
	if err != nil {
		return err
	}
	owner, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	holder, err := sid.Parse(owner)
	if err != nil {
		return err
	}

	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return fmt.Errorf("reading the permissions of %s: error %d", path, r)
	}
	defer w32.Free(descriptor)

	held, err := allEntries(dacl)
	if err != nil {
		return fmt.Errorf("reading the permissions of %s: %w", path, err)
	}

	var list []explicitAccess
	var taken uint32
	for _, one := range held {
		// What this account holds is about to be set outright, refusals and
		// all. Carrying the old entries over first would keep them: a
		// directory narrowed to read-only carries a refusal, and widening it
		// again would leave that refusal standing in front of the new
		// permission, which is the whole reason a grant replaces rather than
		// adds.
		if sameSID(one.trustee.name, value) {
			continue
		}
		if sharedWrite(one, everyone, users) {
			taken |= one.permissions &^ AccessReadExecute
			one.permissions = AccessReadExecute
		}
		list = append(list, one)
	}
	// Those two may have been the only thing letting the person who owns this
	// machine write here, and they are not who is being kept out: a grant must
	// not cost somebody the directory they were granting. Whatever was taken
	// from the crowd is handed straight back to them by name.
	if taken != 0 {
		list = append(list, entry(holder, taken, reach, grantAccess))
	}
	list = append(list, listFor(value, entries)...)
	return publish(path, list, true)
}

// allEntries walks an access control list entry by entry and returns what it
// holds, ready to be written back as the object's own.
//
// It reads the entries itself rather than asking GetExplicitEntriesFromAcl,
// which answers with the object's own entries alone and leaves out everything
// a directory above handed down — exactly the entries this has to rewrite.
// The mark that says an entry was handed down is dropped on the way through,
// which is what makes the rewritten list the object's own.
//
// The identifiers point into the list being read, so what is returned stays
// usable only for as long as the security description holding it does.
func allEntries(dacl *aclHeader) ([]explicitAccess, error) {
	if dacl == nil {
		return nil, nil
	}
	const (
		allowed          = 0
		refused          = 1
		inheritanceFlags = InheritObjects | InheritContainers | InheritNoPropagate | InheritOnly
		trusteeIsSID     = 0
		trusteeIsUnknown = 5
		headerAndMask    = 8 // the entry's own header, then the access it covers
	)
	held := make([]explicitAccess, 0, dacl.count)
	for i := uint16(0); i < dacl.count; i++ {
		var ace *aceHeader
		if r, _, err := procGetAce.Call(uintptr(unsafe.Pointer(dacl)), uintptr(i),
			uintptr(unsafe.Pointer(&ace))); r == 0 {
			return nil, fmt.Errorf("reading entry %d: %w", i, err)
		}
		mode := int32(grantAccess)
		switch ace.kind {
		case allowed:
		case refused:
			mode = denyAccess
		default:
			// Rewriting a list means writing back everything in it. An entry
			// of a kind this cannot carry over would be dropped silently, and
			// dropping a refusal is how a boundary quietly stops holding.
			return nil, fmt.Errorf("entry %d is of a kind that cannot be carried over (%d)", i, ace.kind)
		}
		held = append(held, explicitAccess{
			permissions: ace.mask,
			mode:        mode,
			inheritance: uint32(ace.flags) & inheritanceFlags,
			trustee: trustee{
				form: trusteeIsSID, kind: trusteeIsUnknown,
				name: uintptr(unsafe.Pointer(ace)) + headerAndMask,
			},
		})
	}
	return held, nil
}

// sameSID reports whether two identifiers are the same one.
func sameSID(a, b uintptr) bool {
	same, _, _ := procEqualSid.Call(a, b)
	return same != 0
}

// sharedWrite reports whether an entry lets Everyone or BUILTIN\Users change
// something. Those two are the identifiers every sandbox's restricted list
// carries, so an entry naming either of them is an entry every sandbox holds.
func sharedWrite(held explicitAccess, everyone, users uintptr) bool {
	const trusteeIsSID = 0
	if held.mode != grantAccess || held.trustee.form != trusteeIsSID {
		return false
	}
	if held.permissions&writeMask == 0 {
		return false
	}
	return sameSID(held.trustee.name, everyone) || sameSID(held.trustee.name, users)
}
