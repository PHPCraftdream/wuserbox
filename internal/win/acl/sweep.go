// Narrowing the tree under a directory that has just been handed over.
//
// Rewriting the directory itself is not enough: an object inside it whose
// permissions are its own no longer hears from above, so whatever Everyone
// or BUILTIN\Users hold there survives the grant and every sandbox that
// holds the tree can write through it. The whole tree is read before any of
// it is changed, so the ordinary reason to stop happens before anything has
// moved.

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
