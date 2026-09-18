// Taking a grant back reaches further than the directory that was granted.
//
// Rewriting the directory takes the account's entries off it, and what the
// directory stops handing down goes with that. What it does not reach is an
// object the sandbox's own account created while the grant was writable: it
// holds nothing of its own that names the account, so StripOwn passes it, and
// what it keeps is the one thing no entry refuses -- the WRITE_DAC and
// READ_CONTROL ownership implies, counted after every refusal the list makes
// (owner.go). The narrowing side of this has the sweep and its cap; a revoke
// had nothing. The cap the narrowing side writes is set out in owner.go; this
// is the same cap written on the way out.

package acl

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// TakeBack takes account's entries off root and everything under it, and caps
// what the owner of an object the sandbox owns holds implicitly -- the same
// cap the sweep writes (owner.go), written here on the way out rather than on
// the way in.
//
// pinned names the paths the record holds for this sandbox. Their subtrees
// are passed over, the same keep-list grant.Prune has always kept: a
// directory granted in its own right holds on different terms, and taking a
// grant away from one tree must not take the pinned one down with it. The
// record is also the only evidence of a seal that is accepted here: an object
// whose list is its own could have been written by the sandbox that owns it,
// and the shape of a list is not evidence about who wrote it.
//
// Unlike the sweep, the walk takes the root itself too: the sweep skips it
// because Isolate publishes it, and nothing publishes here.
func TakeBack(root, account string, pinned []string) error {
	if _, err := sid.Parse(account); err != nil {
		return err
	}
	operator, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	operatorSID, err := sid.Parse(operator)
	if err != nil {
		return err
	}
	systemSID, err := sid.Parse(sid.System)
	if err != nil {
		return err
	}
	administratorsSID, err := sid.Parse(sid.Administrators)
	if err != nil {
		return err
	}
	limited, err := sid.Parse(sid.OwnerRights)
	if err != nil {
		return err
	}
	mark, err := sid.Parse(handDownMark)
	if err != nil {
		return err
	}
	sandbox, err := sandboxIdentities(account)
	if err != nil {
		return err
	}
	spared := make(map[string]bool, len(pinned))
	for _, one := range pinned {
		if !strings.EqualFold(one, root) {
			spared[strings.ToLower(one)] = true
		}
	}
	return filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		switch {
		case err != nil:
			// A place that cannot be read is a place nothing can be
			// promised about, so this is not passed over quietly -- the
			// same rule walkTree applies.
			return fmt.Errorf("looking through %s: %w", name, err)
		case entry.Type()&os.ModeSymlink != 0:
			return nil // a name for somewhere else, whose permissions are its own
		}
		if spared[strings.ToLower(name)] {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		return takeBack(name, sandbox, limited, mark, operatorSID, systemSID, administratorsSID)
	})
}

// takeBack is one object's share of taking a grant back: the account's own
// entries go, and an object the sandbox's account owns has the cap written
// onto it, once, in the same update -- measured on the narrowing side, once
// the cap has landed the owner can no longer edit the list at all, so a cap
// that arrives late arrives never (owner.go).
func takeBack(path string, sandbox []uintptr, limited, mark, operator, system, administrators uintptr) error {
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo|ownerInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return fmt.Errorf("reading the permissions of %s: error %d", path, r)
	}
	defer w32.Free(descriptor)

	held, err := entriesOf(dacl)
	if err != nil {
		return fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	owned := ownedByTheSandbox(ownerOf(descriptor), sandbox)
	var clear []explicitAccess
	for _, one := range held {
		if one.inherited || !matchesSandboxIdentity(one.access.trustee.name, sandbox) {
			continue
		}
		already := false
		for _, prior := range clear {
			if sameSID(prior.trustee.name, one.access.trustee.name) {
				already = true
				break
			}
		}
		if !already {
			clear = append(clear, entry(one.access.trustee.name, 0, InheritNone, setAccess))
		}
	}
	holdsOwn := len(clear) != 0

	if !owned {
		// Somebody else's object keeps everything except the account's own
		// entries: a grant pinned deeper inside the tree is not this
		// revoke's to take down, only the pinned copy of this account's
		// entry is. This is StripOwn's decision, made where the cap is
		// decided so that one read answers both questions.
		if !holdsOwn {
			return nil
		}
		return apply(path, clear, false)
	}

	if hearsFromAbove(held) {
		// The list still hears from the directory above, but this object is
		// owned by the sandbox. Writing it whole is the same rule as the
		// narrowing sweep: remove the sandbox identities, cap ownership, and
		// narrow every unexpected changing grant before a new restricted
		// process can open the object. Keeping the old incremental update here
		// left an explicit Everyone:Full Control beside the inherited grant.
		carried, _ := carryRevokeEntries(held, sandbox, operator, system, administrators)
		return writeWhole(path, carried, nil, nil, limited, mark)
	}

	// The object's list is its own: written whole by an earlier sweep, whose
	// mark it carries, or written by the sandbox itself while it owned the
	// object -- and the shape of a list is not evidence about which. The
	// account's entries go either way: a grant the sandbox handed itself
	// ("icacls /grant *self:(F)") survives a revoke that only strips the
	// group's entries, and the cap alone does not touch it -- the cap
	// replaces only what ownership implies; what the list itself grants the
	// account, it goes on granting.
	if holdsOwn {
		// One account's access comes off, and nobody else's: the rest of
		// the list -- the hand-down of an earlier moment, the operator's
		// entries among it -- is carried over, and the whole write keeps
		// the list protected so it goes on hearing from nobody. Explicit
		// changing rights are retained only for identities the operator
		// deliberately relies on; a sandbox can write an Everyone:Full
		// Control entry before revoke, and that entry must not survive the
		// cap merely because it is explicit.
		carried, _ := carryRevokeEntries(held, sandbox, operator, system, administrators)
		return writeWhole(path, append(clear, carried...), nil, nil, limited, mark)
	}
	if capPresent(held, limited) {
		// A cap by itself is not proof that the list is safe: an earlier
		// revoke could have accepted an owner-rights entry while an
		// unexpected explicit broad grant stood beside it. Normalize that
		// list before treating the fast path as finished.
		carried, changed := carryRevokeEntries(held, sandbox, operator, system, administrators)
		if !changed {
			return nil
		}
		return writeWhole(path, carried, nil, nil, limited, mark)
	}
	// Nothing of the account's was on it and there is no list to carry: a
	// list with no entries refuses everybody everything, which is one step
	// further than taking one account's access away -- the cap is written
	// onto a whole list of its own instead, which leaves the owner reading
	// and the mark saying who wrote it.
	//
	// An object carrying no list at all lands here too, with held empty, and
	// that is deliberate: no list is the widest an object gets, every
	// account on the machine holding everything through it, and capping a
	// list-less object the sandbox owns writes a whole list of its own
	// because leaving the absence in force would leave it so.
	return writeWhole(path, nil, nil, nil, limited, mark)
}

// revokeCarry decides which explicit permissions may survive a revoke on an
// object owned by the sandbox. Operator recovery and the machine principals
// are part of the product's ACL contract. A grant to another wuserbox group
// is an independent sandbox grant, so it remains intact too. Every other
// changing grant is narrowed to its non-changing rights; otherwise a sandbox
// could pre-write Everyone:Full Control and keep changing the object after
// its own account entry and owner rights had been removed.
func revokeCarry(access explicitAccess, operator, system, administrators uintptr) (explicitAccess, bool) {
	if access.mode != grantAccess || access.permissions&changing == 0 {
		return access, true
	}
	if sameSID(access.trustee.name, operator) || sameSID(access.trustee.name, system) ||
		sameSID(access.trustee.name, administrators) || sandboxGroup(access.trustee.name) {
		return access, true
	}
	access.permissions &^= changing
	return access, access.permissions != 0
}

// carryRevokeEntries keeps the explicit, non-inherited part of an object's
// own list while applying the revoke policy to every changing grant. changed
// reports whether any entry was removed or narrowed, which is what invalidates
// the already-capped fast path.
func carryRevokeEntries(held []heldEntry, sandbox []uintptr, operator, system, administrators uintptr) ([]explicitAccess, bool) {
	var carried []explicitAccess
	changed := false
	for _, one := range held {
		if one.inherited || matchesSandboxIdentity(one.access.trustee.name, sandbox) {
			continue
		}
		access, keep := revokeCarry(one.access, operator, system, administrators)
		if access.permissions != one.access.permissions || !keep {
			changed = true
		}
		if keep {
			carried = append(carried, access)
		}
	}
	return carried, changed
}

// sandboxGroup recognizes only groups created by wuserbox. Resolving a SID
// can fail for a stale or synthetic ACL entry; failing closed narrows that
// entry rather than treating an unknown principal as trusted.
func sandboxGroup(value uintptr) bool {
	name, err := sid.Name(value)
	return err == nil && group.IsSandbox(name)
}
