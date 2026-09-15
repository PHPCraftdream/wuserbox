package acl

import (
	"fmt"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
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
	if dacl == nil {
		// Nothing to carry over, because there was no list -- which is not an
		// empty list but the widest an object gets, everybody holding every
		// right. Writing only the grant on top of that left a directory whose
		// permissions named the sandbox and nobody else: the owner could not
		// write their own directory afterwards, measured. What the absence gave
		// everybody is written down instead, narrowed, and the grant is added
		// to it.
		seed, err := fromNothing(holder)
		if err != nil {
			return err
		}
		list = seed
	}
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
			// Taken away, not replaced. Assigning read-and-execute here would
			// hand reading to an entry that only covered writing, which is a
			// widening dressed as a narrowing: measured, a directory whose
			// only entry for Everyone was write-data became readable by every
			// sandbox and every account on the machine the moment it was
			// granted. Taking the changing rights out of what is already
			// there cannot do that. For Modify it lands on read-and-execute
			// anyway, which is where the plain case ends up.
			taken |= one.permissions & changing
			one.permissions &^= changing
			if one.permissions == 0 {
				continue // nothing left to say about them
			}
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
	// What is inside is put right before the grant itself is written, and the
	// order is the whole of the care here.
	//
	// The sweep walks a tree and can fail anywhere in it: a directory that
	// cannot be read, an entry of a kind that cannot be carried over. Writing
	// the grant first meant such a failure left the sandbox holding this
	// directory while the caller undid the record, and a permission in force
	// that the record does not mention cannot be found again -- explain does
	// not list it and revoke does not know about it. Failing before anything
	// is granted leaves nothing behind instead.
	//
	// Both halves narrow rather than widen, so stopping between them can only
	// take Everyone's and Users' write access off what is inside, which is
	// what the grant was going to do anyway.
	if err := sweep(path, everyone, users, holder); err != nil {
		return err
	}
	return publish(path, list, true)
}

// fromNothing is the list that stands for an absent one, narrowed.
//
// It is built in one place because two callers need the same answer: the
// sweep, writing it onto an object inside a granted tree, and the grant
// itself, where the directory being handed over is the one with no list. The
// second was missed at first, and a grant on such a directory published a list
// naming the sandbox alone -- the owner locked out of their own directory by
// the act of granting it.
func fromNothing(holder uintptr) ([]explicitAccess, error) {
	const subtree = InheritObjects | InheritContainers
	const fullControl = 0x1F01FF
	list := []explicitAccess{entry(holder, fullControl, subtree, grantAccess)}
	for _, known := range []string{sid.System, sid.Administrators} {
		value, err := sid.Parse(known)
		if err != nil {
			return nil, err
		}
		list = append(list, entry(value, fullControl, subtree, grantAccess))
	}
	everyone, err := sid.Parse(sid.Everyone)
	if err != nil {
		return nil, err
	}
	return append(list, entry(everyone, fullControl&^changing, subtree, grantAccess)), nil
}

// giveAList writes a permission list onto an object that has none.
//
// Every one of these is a narrowing, which is the only thing that makes it
// safe to do at all. An object with no list grants everybody every right, so
// whatever is written can only take away: Everyone is left with what remains
// of that once the changing rights are gone, which is reading and executing,
// and the owner, the system and administrators keep what they already had in
// full. Naming those three is not generosity either -- they held everything a
// moment ago through the same absence, and writing a list that left them out
// would take it from them.
//
// It is written as a change rather than as the whole list, so that whatever a
// directory above hands down still arrives here afterwards, the same as for
// every other object the sweep touches.
func giveAList(path string, holder uintptr) error {
	list, err := fromNothing(holder)
	if err != nil {
		return err
	}
	return apply(path, list, false)
}
