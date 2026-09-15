// Reading the permission list Windows keeps for an object, entry by entry,
// and the questions worth asking of it: who may write here, and does this
// account read this path at all.
//
// GetExplicitEntriesFromAcl answers with the entries the object holds in its
// own right and says nothing about the ones handed down to it, which is a
// different question from the one being asked here: what reaches this object,
// from wherever. So the list is walked directly instead.

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
	found, err := entriesOf(dacl)
	if err != nil {
		return nil, err
	}
	held := make([]explicitAccess, 0, len(found))
	for _, one := range found {
		held = append(held, one.access)
	}
	return held, nil
}

// heldEntry is one entry and where it came from: an object's own, or a copy a
// directory above handed down.
type heldEntry struct {
	access    explicitAccess
	inherited bool
}

// entriesOf walks a permission list entry by entry, keeping track of which
// entries the object holds itself. Rewriting a whole list wants all of them;
// narrowing what an object holds on its own wants only the ones it owns.
func entriesOf(dacl *aclHeader) ([]heldEntry, error) {
	if dacl == nil {
		return nil, nil
	}
	const (
		allowed          = 0
		refused          = 1
		inheritanceFlags = InheritObjects | InheritContainers | InheritNoPropagate | InheritOnly
		inheritedAce     = 0x10
		trusteeIsSID     = 0
		trusteeIsUnknown = 5
		headerAndMask    = 8 // the entry's own header, then the access it covers
	)
	held := make([]heldEntry, 0, dacl.count)
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
		held = append(held, heldEntry{
			inherited: ace.flags&inheritedAce != 0,
			access: explicitAccess{
				permissions: ace.mask,
				mode:        mode,
				inheritance: uint32(ace.flags) & inheritanceFlags,
				trustee: trustee{
					form: trusteeIsSID, kind: trusteeIsUnknown,
					name: uintptr(unsafe.Pointer(ace)) + headerAndMask,
				},
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

// sharedWrite reports whether an entry lets one of the identities every
// sandbox carries change something, which makes it an entry every sandbox
// holds however the directory was meant to be handed out.
//
// Authenticated Users is the third of them and was missing. It cost nothing
// while a sandbox was a restricted token, because that token's second check
// never carried it: an entry naming it reached nobody inside. An account
// carries it by virtue of having logged on, so a directory handed to one
// sandbox with Authenticated Users:Modify left standing on it was writable,
// and deletable, by every other sandbox on the machine.
func sharedWrite(held explicitAccess, shared ...uintptr) bool {
	const trusteeIsSID = 0
	if held.mode != grantAccess || held.trustee.form != trusteeIsSID {
		return false
	}
	if held.permissions&changing == 0 {
		return false
	}
	for _, one := range shared {
		if sameSID(held.trustee.name, one) {
			return true
		}
	}
	return false
}

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
