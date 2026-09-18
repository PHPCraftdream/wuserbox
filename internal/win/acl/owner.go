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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
// account's name -- the identifier of every member of the local group that
// identifier names. Files a sandbox creates are owned by its account, not by
// its group, so a check on the group's identifier alone would match nothing
// a sandbox owns.
//
// The group answers with names, and a name is not SID text. Measured on this
// desk, non-elevated:
//
//	ConvertStringSidToSidW("Computer") -> 1337 ERROR_INVALID_SID
//	LookupAccountNameW("Computer")     -> S-1-5-21-716976243-447150123-4053037466-1001
//	LookupAccountNameW("PC\Computer")  -> the same SID
//
// So a member's name parsed as SID text fails for every real member, and
// swallowing that error left this list holding the group alone: the owner
// check matched nothing and the cap never landed. Members are resolved with
// LookupAccountNameW instead, and one that cannot be resolved fails the
// whole list -- a member of a group that exists must not come out as a
// shorter list, which quietly protects less.
//
// Where the identifier names no account at all -- a synthetic identifier in
// tests -- LookupAccountNameW refuses, there is no group to ask, and the one
// identifier is the whole answer. Where it names a plain account, the group
// lookup answers that there is no such group and the answer is the same.
func sandboxIdentities(account string) ([]uintptr, error) {
	value, err := sid.Parse(account)
	if err != nil {
		return nil, err
	}
	identities := []uintptr{value}
	// Whether value resolves to an account name at all is a fact, not an
	// error: a synthetic identifier in tests resolves to none, there is no
	// group to ask, and the one identifier already collected is the whole,
	// correct answer.
	name, named := accountNameOf(value)
	if !named {
		return identities, nil
	}
	members, err := localGroupMembers(name)
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		resolved, err := sid.Lookup(member)
		if err != nil {
			return nil, fmt.Errorf("resolving %s, a member of %s: %w", member, name, err)
		}
		pin(resolved)
		identities = append(identities, uintptr(unsafe.Pointer(&resolved[0])))
	}
	return identities, nil
}

// accountNameOf answers whether value resolves to an account name at all,
// which is the one question sandboxIdentities needs from sid.Name: a SID
// with no name (a synthetic identifier in tests) is not a lookup failure to
// propagate, it is the answer.
func accountNameOf(value uintptr) (string, bool) {
	name, err := sid.Name(value)
	return name, err == nil
}

var (
	pinnedMu sync.Mutex
	// pinned keeps every identifier Lookup resolved from a group member's
	// name alive for as long as the process lives. The identities list
	// holds uintptrs, and a KeepAlive -- what setHiveSecurity in
	// internal/account pins a value with -- lasts one call, while these
	// pointers have to answer for owner checks across a whole tree walk.
	// Keeping them here gives them the lifetime sid.Parse's results
	// already have: never freed, because something is holding them.
	pinned []sid.Value
)

// pin gives a Lookup result the lifetime Parse's results already have. The
// mutex is because grants can be applied from several goroutines at once
// (state.ApplyTogether).
func pin(value sid.Value) {
	pinnedMu.Lock()
	defer pinnedMu.Unlock()
	pinned = append(pinned, value)
}

var (
	procGroupMembers = w32.Netapi32.NewProc("NetLocalGroupGetMembers")
	procFreeBuffer   = w32.Netapi32.NewProc("NetApiBufferFree")
)

// localGroupMembers lists the account names belonging to a local group, the
// same question the account package asks the same call. It is asked again
// here rather than called there because the account package builds on this
// one, and the owner check cannot work without the answer.
//
// The names come back qualified -- "PC\Computer", not "Computer" -- and
// stay that way: the qualified form is what Windows itself handed back and
// the only form that cannot answer for another principal of the same name.
// sid.Lookup resolves it.
//
// A name that is not a local group is not a failure. Measured on this desk,
// non-elevated, one group under both spellings and a name that is none:
//
//	NetLocalGroupGetMembers("Computer")          -> 1376 ERROR_NO_SUCH_ALIAS
//	NetLocalGroupGetMembers("PC\Computer")       -> 2220 NERR_GroupNotFound
//	NetLocalGroupGetMembers("no-such-group-xyz") -> 2220
//	NetLocalGroupGetMembers("Administrators")    -> 0, members
//	                                                "PC\Administrator",
//	                                                "PC\Computer", "PC\User"
//
// Any other answer is an enumeration that failed for a group that may well
// exist, and must not come back as an empty list.
func localGroupMembers(name string) ([]string, error) {
	type memberInfo3 struct{ domainAndName *uint16 }
	var members *memberInfo3
	var read, total uint32
	const most = 0xFFFFFFFF
	r, _, _ := procGroupMembers.Call(0, uintptr(unsafe.Pointer(w32.UTF16(name))), 3,
		uintptr(unsafe.Pointer(&members)), most, uintptr(unsafe.Pointer(&read)),
		uintptr(unsafe.Pointer(&total)), 0)
	if r == 1376 || r == 2220 {
		return nil, nil
	}
	if r != 0 {
		return nil, fmt.Errorf("listing the members of %s: error %d", name, r)
	}
	defer procFreeBuffer.Call(uintptr(unsafe.Pointer(members)))
	var out []string
	for _, one := range unsafe.Slice(members, read) {
		out = append(out, w32.GoString(one.domainAndName))
	}
	return out, nil
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
	return matchesSandboxIdentity(owner, sandbox)
}

// matchesSandboxIdentity reports whether trustee is any identity that can
// represent this sandbox. Production ACLs name the local group, while files
// created by the account are owned by the account and a program can add an
// ACE for that account directly. Treating only the group as the sandbox leaves
// that direct ACE behind during a revoke or a narrowing.
func matchesSandboxIdentity(trustee uintptr, sandbox []uintptr) bool {
	if trustee == 0 {
		return false
	}
	for _, one := range sandbox {
		if one != 0 && sameSID(trustee, one) {
			return true
		}
	}
	return false
}

// capObject writes the finished list of an object the sandbox's account owns,
// and which of two things it does follows from what the object's list says
// now:
//
//   - hearing from above, it is written whole: its own entries -- the crowd
//     among them narrowed --, the hand-down, the cap and the mark. The
//     inherited entries it held are replaced by the hand-down written in
//     explicitly, because a list written individually no longer hears from
//     above. Measured through Isolate, against a file carrying an inherited
//     Modify from its tree's writable days:
//
//     without the cap: the sweep writes nothing, the publish lands, (I)(M) becomes (I)(RX)
//     with the cap:    the sweep writes the cap, the publish lands, (I)(M) stays, write accepted
//
//     The second is a narrowing that does not narrow, which is worse than the
//     hole the cap closes.
//
//   - holding nothing inherited, marked or forged alike, it is written whole
//     with the current hand-down, the cap and the mark. Where the hand-down
//     and the cap are already current, nothing is written at all: a tree of
//     a hundred thousand files the sandbox created is swept on every init,
//     and rewriting them all every time is a cost with nothing to show for
//     it.
//
// A third rule used to spare whatever held nothing inherited and no mark,
// reading that shape as somebody having sealed the object against its owner
// on purpose, and it spared a directory with its whole subtree. The shape can
// be written by the sandbox itself while it owns the object -- emptying its
// own list is a right ownership implies -- and it is indistinguishable from
// a seal the operator pinned, so a narrowing left the sandbox's own direct
// permissions and its implicit WRITE_DAC standing on exactly the objects the
// sandbox chose. What an object is spared on now is the record, not its
// list: pinned holds the paths the operator granted in their own right, and
// a directory named there is skipped with its subtree, the same keep-list
// rule grant.Prune has always applied.
func capObject(path string, held []heldEntry, narrowed, handback []explicitAccess, hand []explicitAccess, owner, mark uintptr, pinned map[string]bool) error {
	if pinned[strings.ToLower(path)] {
		info, err := os.Lstat(path)
		if err == nil && info.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
	if hearsFromAbove(held) {
		return writeWhole(path, narrowed, handback, hand, owner, mark)
	}
	if alreadyCapped(held, hand, owner) {
		return nil
	}
	return writeWhole(path, nil, nil, hand, owner, mark)
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
