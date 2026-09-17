// Capping what an object's owner holds without asking.
//
// Windows gives whoever owns an object READ_CONTROL and WRITE_DAC whether the
// permission list says so or not, and it counts the implicit grant after it
// has counted refusals. That is a way out of every narrowing this package
// writes. Measured on a file the caller owns, without elevation, its list
// refusing WRITE_DAC to the owner's own identifier:
//
//	[1] echo tampered> f.txt            write refused
//	[0] icacls f.txt /grant *<me>:(F)   the list was rewritten anyway
//	[0] echo tampered> f.txt            write accepted, content changed
//
// An OWNER RIGHTS entry -- the well-known identifier S-1-3-4 -- replaces the
// implicit grant with whatever the entry carries, and the owner cannot take
// the entry off once it is there. Measured on the same desk, the entry
// carrying read-and-execute:
//
//	[5] icacls g.txt /grant *<me>:(F)   refused
//	[5] icacls g.txt /setowner *<me>    refused
//	[5] icacls g.txt /remove *S-1-3-4   refused -- the owner cannot take it off
//
// Two more facts from the same measurement shape the code below. The entry
// has to go into the same update as the rest of the list: once it has landed
// the owner can no longer edit the list at all, so a second call that tries
// to finish the job is refused -- the third icacls of that session came back
// access denied, because the cap the second had written had already taken
// WRITE_DAC away. And the cap replaces only what ownership implies: entries
// naming the account still grant what they grant, so a write handed to
// another identity in the same list went ahead under the cap. Refusing a
// write stays the list's own business; this is only about the part the owner
// was holding behind the list's back.
//
// Recovery is where it always was: deleting through the parent directory.
// Deleting asks for DELETE on the object or FILE_DELETE_CHILD on its parent,
// and the cap takes neither from the operator -- measured, the locked file
// went when the parent's right was used.

package acl

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// ownerInfo asks GetNamedSecurityInfo for the owner alongside the list, in
// the call every writer here was already making.
const ownerInfo = 0x1

// handDownMark is the identifier the hand-down mark is named to: the NULL
// SID. It matches no security principal there ever was, so an entry naming
// it grants nothing to anyone -- measured, a protected list holding only
// NULL SID:(F) refused its own owner both writing and reading, with the
// owner's implicit rights otherwise untouched. What it carries is
// provenance: the list it sits in was written whole by the sweep, and its
// entries mirror the hand-down of an earlier moment rather than anybody's
// decision about this object. CREATOR OWNER could not be used for this: the
// system substitutes the object owner's identifier for it when the entry is
// written, and the mark dissolves -- measured.
const handDownMark = "S-1-0-0"

var procGetSecurityDescriptorOwner = w32.Advapi32.NewProc("GetSecurityDescriptorOwner")

// ownerLimit is the pair of entries that caps the owner of an object the
// sandbox owns: whatever an owner-rights entry said before is replaced, and
// the owner is left with read-and-execute.
//
// Read-and-execute, because the rights that have to go are the ones that
// change an object or decide who may -- WRITE_DAC and WRITE_OWNER, every bit
// of changing, and delete, which was never an owner right. What remains is
// what a read-only grant gives, and no more. The owner of a file is the
// account that wrote it, and reading its own content back is not what a
// narrow or a revoke is for; READ_CONTROL alone would hold the line too and
// would take the reading as well, which is a second decision smuggled into
// the first. Naming OWNER RIGHTS at all is what switches the implicit grant
// off; what the entry carries is then all the owner has.
func ownerLimit(ownerRights uintptr) []explicitAccess {
	return []explicitAccess{
		// Replaces any owner-rights entry already there, refusals included.
		// One granting the owner full control would defeat this one, and two
		// entries saying different things about the same identifier is one
		// more thing to rule out when something behaves differently.
		//
		// It leaves a visible residue and that is deliberate: where there was
		// nothing to replace, this lands as an entry carrying no rights at
		// all, so `icacls` on a swept file prints an empty "OWNER RIGHTS:"
		// line above the real one. The alternative is to drop it and filter
		// owner-rights entries out of everything that builds a list instead
		// -- both the carried entries here and the preserved entries in
		// Isolate -- which trades one entry granting nothing for a guarantee
		// that has to be repeated in two places and stay repeated. So the
		// line stays, and this says why rather than leaving it to look like
		// a bug worth tidying.
		entry(ownerRights, 0, InheritNone, setAccess),
		entry(ownerRights, AccessReadExecute, InheritNone, grantAccess),
	}
}

// markFor is the hand-down mark as an entry: the NULL SID, reading, no
// inheritance. Written only by the sweep's whole write, and only ever
// recognized by it.
func markFor(mark uintptr) explicitAccess {
	return entry(mark, AccessReadExecute, InheritNone, grantAccess)
}

// sandboxIdentities lists every identifier the sandbox whose access is being
// decided goes by: the account the entries are written to, and -- because
// entries go out under a group's name while ownership accrues under the
// account's name -- the accounts that belong to the local group that
// identifier names. Files a sandbox creates are owned by its account, not by
// its group, so a check on the group's identifier alone would match nothing a
// sandbox owns.
//
// Where the identifier names no local group -- a synthetic identifier in
// tests, a plain account -- the member lookup fails and the one identifier is
// the whole answer.
func sandboxIdentities(account string) []uintptr {
	value, err := sid.Parse(account)
	if err != nil {
		return nil
	}
	identities := []uintptr{value}
	name, err := sid.Name(value)
	if err != nil {
		return identities
	}
	for _, member := range localGroupMembers(name) {
		if parsed, err := sid.Parse(member); err == nil {
			identities = append(identities, parsed)
		}
	}
	return identities
}

var (
	procGroupMembers = w32.Netapi32.NewProc("NetLocalGroupGetMembers")
	procFreeBuffer   = w32.Netapi32.NewProc("NetApiBufferFree")
)

// localGroupMembers lists the plain account names belonging to a local group,
// the same question the account package asks the same call. It is asked again
// here rather than called there because the account package builds on this
// one, and the owner check cannot work without the answer.
func localGroupMembers(name string) []string {
	type memberInfo3 struct{ domainAndName *uint16 }
	var members *memberInfo3
	var read, total uint32
	const most = 0xFFFFFFFF
	r, _, _ := procGroupMembers.Call(0, uintptr(unsafe.Pointer(w32.UTF16(name))), 3,
		uintptr(unsafe.Pointer(&members)), most, uintptr(unsafe.Pointer(&read)),
		uintptr(unsafe.Pointer(&total)), 0)
	if r != 0 {
		return nil
	}
	defer procFreeBuffer.Call(uintptr(unsafe.Pointer(members)))
	var out []string
	for _, one := range unsafe.Slice(members, read) {
		member := w32.GoString(one.domainAndName)
		if i := strings.LastIndexByte(member, '\\'); i >= 0 {
			member = member[i+1:]
		}
		out = append(out, member)
	}
	return out
}

// ownerOf answers with the identifier that owns the object whose security
// descriptor this is, or 0 where there is none to name.
func ownerOf(descriptor uintptr) uintptr {
	var owner uintptr
	var defaulted int32
	if r, _, _ := procGetSecurityDescriptorOwner.Call(descriptor,
		uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return 0
	}
	return owner
}

// ownedByTheSandbox reports whether the owner of an object is one of the
// identifiers the sandbox goes by.
func ownedByTheSandbox(owner uintptr, sandbox []uintptr) bool {
	if owner == 0 {
		return false
	}
	for _, one := range sandbox {
		if sameSID(owner, one) {
			return true
		}
	}
	return false
}

// capObject writes the finished list of an object the sandbox's account owns,
// and which of three things it does follows from what the object's list says
// now:
//
//   - hearing from above, it is written whole: its own entries -- the crowd
//     among them narrowed, the rest carried over --, the hand-down, the cap
//     and the mark. The inherited entries it held are replaced by the
//     hand-down written in explicitly, because a list written individually
//     no longer hears from above. Measured through Isolate, against a file
//     carrying an inherited Modify from its tree's writable days:
//
//     without the cap: the sweep writes nothing, the publish lands, (I)(M) becomes (I)(RX)
//     with the cap:    the sweep writes the cap, the publish lands, (I)(M) stays, write accepted
//
//     The second is a narrowing that does not narrow, which is worse than the
//     hole the cap closes.
//
//   - holding the mark and nothing inherited, it was written by a previous
//     sweep, and the same rule applies one step on: the mark's whole write is
//     what stopped it hearing from above, so the current hand-down replaces
//     the one it carries. Measured the other way round, with the mark not
//     checked: a file carrying the writable grant's Modify kept it through
//     the read-only narrowing that followed, and the write was accepted --
//     and narrowed back, the same skip would have kept a refusal standing
//     through every widening after it. Where the hand-down and the cap are
//     already current, nothing is written at all: a tree of a hundred
//     thousand files the sandbox created is swept on every init, and
//     rewriting them all every time is a cost with nothing to show for it.
//
//   - holding neither, it is somebody's own -- a grant in its own right,
//     pinned where it sits, or sealed against its owner -- and it is left
//     alone, a directory with its whole subtree. A granted directory is
//     capped at its own top and carries no mark, which is what keeps a
//     narrowing from above from rewriting a grant that holds on different
//     terms: the same decision Prune's keep-list makes for recorded grants,
//     made here from the list alone. The cap is not added to a sealed object
//     either: giving its owner read would widen.
//
// What the mark buys is the difference between the second rule and the
// third. Nothing inherited says two opposite things -- the sweep wrote this,
// or somebody sealed this -- and they want opposite treatment.
func capObject(path string, held []heldEntry, narrowed, handback []explicitAccess, everyone, users uintptr, hand []explicitAccess, owner, mark uintptr) error {
	marked := holdsEntry(held, markFor(mark))
	switch {
	case hearsFromAbove(held):
		// The object's own entries that the crowd loop did not touch go in
		// verbatim: dropping them wrote sealed lists down to the hand-down
		// and the cap, and a protected object the sandbox owns lost what it
		// held.
		var carried []explicitAccess
		for _, one := range held {
			if one.inherited || sameSID(one.access.trustee.name, everyone) || sameSID(one.access.trustee.name, users) {
				continue
			}
			carried = append(carried, one.access)
		}
		return writeWhole(path, append(narrowed, carried...), handback, hand, owner, mark)
	case marked:
		if alreadyCapped(held, hand, owner) {
			return nil
		}
		return writeWhole(path, nil, nil, hand, owner, mark)
	default:
		info, err := os.Lstat(path)
		if err == nil && info.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
}

// hearsFromAbove reports whether the object's list still holds anything a
// directory above handed down. A list holding none is its own -- protected,
// or written whole by a previous sweep -- and what reaches it from above is
// not this call's to decide.
func hearsFromAbove(held []heldEntry) bool {
	for _, one := range held {
		if one.inherited {
			return true
		}
	}
	return false
}

// alreadyCapped reports whether the object holds the current hand-down and
// the cap already, entry for entry, so writing it again would change nothing.
func alreadyCapped(held []heldEntry, hand []explicitAccess, owner uintptr) bool {
	if !capPresent(held, owner) {
		return false
	}
	for _, want := range hand {
		if !holdsEntry(held, want) {
			return false
		}
	}
	return true
}

// capPresent reports whether the list carries the cap: an owner-rights entry
// granting read-and-execute, which is what the replacement and the grant in
// ownerLimit together leave behind.
func capPresent(held []heldEntry, owner uintptr) bool {
	for _, one := range held {
		if one.access.mode == grantAccess && one.access.permissions == AccessReadExecute &&
			sameSID(one.access.trustee.name, owner) {
			return true
		}
	}
	return false
}

// holdsEntry reports whether the list holds one entry that says the same
// thing as the one given: the same identifier, the same reach, the same
// rights, the same refusal or permission.
func holdsEntry(held []heldEntry, want explicitAccess) bool {
	const trusteeIsSID = 0
	for _, one := range held {
		if one.access.mode != want.mode || one.access.permissions != want.permissions ||
			one.access.inheritance != want.inheritance {
			continue
		}
		if one.access.trustee.form != trusteeIsSID {
			continue
		}
		if sameSID(one.access.trustee.name, want.trustee.name) {
			return true
		}
	}
	return false
}

// writeWhole publishes a finished list for one object: its own entries,
// narrowed; what the crowd held, handed to the holder; the hand-down; the
// cap; and the mark that says this list is the sweep's. Refusals go in ahead
// of permissions, because the list is read in order and a refusal that lands
// after a permission is one the walk never reaches -- the hand-down carries
// the grant's refusal, so the order is built here rather than trusted to the
// order the pieces arrived in.
func writeWhole(path string, narrowed, handback, hand []explicitAccess, owner, mark uintptr) error {
	finished := make([]explicitAccess, 0, len(narrowed)+len(handback)+len(hand)+3)
	for _, mode := range []int32{setAccess, denyAccess, grantAccess} {
		for _, one := range narrowed {
			if one.mode == mode {
				finished = append(finished, one)
			}
		}
		for _, one := range hand {
			if one.mode == mode {
				finished = append(finished, one)
			}
		}
		if mode == grantAccess {
			finished = append(finished, handback...)
		}
	}
	finished = append(finished, ownerLimit(owner)...)
	return apply(path, append(finished, markFor(mark)), true)
}
