package acl

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

// sweep takes the changing rights of Everyone and BUILTIN\Users away from
// everything under path that holds them in its own entries.
//
// Rewriting the directory at the top is not enough on its own. Windows hands
// an inheritable entry down to what is below, but handing it down only
// replaces the handed-down part of a child's list and leaves the child's own
// entries alone — so a directory inside a granted one, carrying an entry of
// its own that lets Users write, stayed writable by every other sandbox.
// Measured, with a peer writing there after the grant.
//
// What is below is not pinned the way the top is. Its own entries are
// narrowed and the rest keeps arriving from the top, which is what lets
// taking the grant away reach it later.
func sweep(root string, everyone, users, holder uintptr) error {
	// Read the whole tree before changing any of it. Doing both in one pass
	// left a failure halfway down with part of the tree already rewritten and
	// the grant not written at all: narrowings nobody asked for and no record
	// anywhere that they happened. Reading first is not a promise -- the tree
	// can change underneath between the passes -- but it turns the ordinary
	// reason for stopping, an entry of a kind that cannot be carried over,
	// into a refusal before anything has moved.
	if err := walkTree(root, func(path string) error {
		_, err := readable(path)
		return err
	}); err != nil {
		return err
	}
	return walkTree(root, func(path string) error {
		return narrowOwn(path, everyone, users, holder)
	})
}

// walkTree visits everything under root that a sweep is allowed to touch.
func walkTree(root string, visit func(string) error) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		switch {
		case err != nil:
			// A place that cannot be read is a place nothing can be promised
			// about, so this is not passed over quietly.
			return fmt.Errorf("looking through %s: %w", path, err)
		case path == root:
			return nil // rewritten already, and pinned
		case entry.Type()&os.ModeSymlink != 0:
			return nil // a name for somewhere else, whose permissions are its own
		}
		return visit(path)
	})
}

// readable reports whether an object's permission list can be carried over,
// and is what the first pass asks of every one of them.
func readable(path string) ([]heldEntry, error) {
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return nil, fmt.Errorf("reading the permissions of %s: error %d", path, r)
	}
	defer w32.Free(descriptor)
	if dacl == nil {
		return nil, nil
	}
	held, err := entriesOf(dacl)
	if err != nil {
		return nil, fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	return held, nil
}

// narrowOwn takes the changing rights of Everyone and BUILTIN\Users out of
// the entries one object holds itself, leaving what it is handed from above
// alone, and hands whatever it took to the owner by name.
//
// The handback is not a courtesy, it is the same rule the granted directory
// itself follows: those two are not who is being kept out, and a grant must
// not cost the person granting it the directory they were granting. One level
// down it was left out, and a directory inside a granted tree that had stopped
// inheriting -- one wuserbox pinned for another sandbox, or one anybody
// protected -- whose only write path was Users went read-only to its owner the
// moment the tree above it was handed over. Measured, by writing a file there
// before and after.
func narrowOwn(path string, everyone, users, holder uintptr) error {
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return fmt.Errorf("reading the permissions of %s: error %d", path, r)
	}
	defer w32.Free(descriptor)

	if dacl == nil {
		// No permission list at all, which Windows reads as everybody having
		// everything -- the widest an object gets. It has no entries, so
		// narrowing them reaches nothing, and a directory inside a granted tree
		// carrying one stayed open to every sandbox on the machine after the
		// tree was handed over. Measured, with a second sandbox writing there.
		return giveAList(path, holder)
	}

	held, err := entriesOf(dacl)
	if err != nil {
		return fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	var update, handback []explicitAccess
	for _, who := range []uintptr{everyone, users} {
		var kept []explicitAccess
		narrowed := false
		for _, one := range held {
			if one.inherited || !sameSID(one.access.trustee.name, who) {
				continue
			}
			access := one.access
			if access.mode == grantAccess && access.permissions&changing != 0 {
				narrowed = true
				// Handed back with the reach the entry it came from had, so
				// the owner keeps exactly what the crowd was holding here and
				// nothing further.
				handback = append(handback,
					entry(holder, access.permissions&changing, access.inheritance, grantAccess))
				access.permissions &^= changing
				if access.permissions == 0 {
					continue
				}
			}
			// Refusals are carried over untouched: taking one away would
			// widen, which is never what this is for.
			kept = append(kept, access)
		}
		if !narrowed {
			continue
		}
		update = append(update, entry(who, 0, InheritNone, setAccess))
		update = append(update, kept...)
	}
	if len(update) == 0 {
		return nil
	}
	return apply(path, append(update, handback...), false)
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
	const subtree = InheritObjects | InheritContainers
	const fullControl = 0x1F01FF
	list := []explicitAccess{entry(holder, fullControl, subtree, grantAccess)}
	for _, known := range []string{sid.System, sid.Administrators} {
		value, err := sid.Parse(known)
		if err != nil {
			return err
		}
		list = append(list, entry(value, fullControl, subtree, grantAccess))
	}
	everyone, err := sid.Parse(sid.Everyone)
	if err != nil {
		return err
	}
	list = append(list, entry(everyone, fullControl&^changing, subtree, grantAccess))
	return apply(path, list, false)
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

// sharedWrite reports whether an entry lets Everyone or BUILTIN\Users change
// something. Those two are the identifiers every sandbox's restricted list
// carries, so an entry naming either of them is an entry every sandbox holds.
func sharedWrite(held explicitAccess, everyone, users uintptr) bool {
	const trusteeIsSID = 0
	if held.mode != grantAccess || held.trustee.form != trusteeIsSID {
		return false
	}
	if held.permissions&changing == 0 {
		return false
	}
	return sameSID(held.trustee.name, everyone) || sameSID(held.trustee.name, users)
}

// StripOwn takes away the entries an object holds itself for one account,
// leaving whatever a directory above hands down to it alone.
//
// It is the other half of pinning a granted directory. Pinning copies what
// the directory was handed into its own list, another sandbox's entry among
// them, and that copy then answers to nobody: taking the other sandbox's
// grant away rewrites the directory it was granted, which this one no longer
// hears from. So the account's access here has to be taken away by name.
func StripOwn(path, account string) error {
	value, err := sid.Parse(account)
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

	held, err := entriesOf(dacl)
	if err != nil {
		return fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	for _, one := range held {
		if one.inherited || !sameSID(one.access.trustee.name, value) {
			continue
		}
		// Only what the object holds itself is cleared. What it is handed from
		// above goes when the directory above is rewritten, which is the
		// caller's next move anyway.
		return apply(path, []explicitAccess{entry(value, 0, InheritNone, setAccess)}, false)
	}
	return nil
}
