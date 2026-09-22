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
	"sync/atomic"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// descriptorReads counts the permission lists this package has asked
// Windows for through the question calls below -- heldBy and the audit
// pass. It is for the close test of asking once per object, and for anyone
// diagnosing a walk: the difference between once per object and once per
// identity asked about is what reading once is for.
var descriptorReads atomic.Int64

// entrySlices counts the lists entriesOf has built. It is for the close
// test of the validation pass, which walks the same entries and builds
// nothing, and for anyone measuring a walk: the preflight answer is two
// facts -- carryable, and whose the object is -- and neither needs the
// entries kept.
var entrySlices atomic.Int64

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
	entrySlices.Add(1)
	held := make([]heldEntry, 0, dacl.count)
	for i := uint16(0); i < dacl.count; i++ {
		one, err := oneEntry(dacl, i)
		if err != nil {
			return nil, err
		}
		held = append(held, one)
	}
	return held, nil
}

// oneEntry reads the i-th entry of a permission list. The trustee points
// into the list being read, so the answer stays usable only for as long
// as the security descriptor holding it does.
func oneEntry(dacl *aclHeader, i uint16) (heldEntry, error) {
	const (
		allowed          = 0
		refused          = 1
		inheritanceFlags = InheritObjects | InheritContainers | InheritNoPropagate | InheritOnly
		inheritedAce     = 0x10
		trusteeIsSID     = 0
		trusteeIsUnknown = 5
		headerAndMask    = 8 // the entry's own header, then the access it covers
	)
	var ace *aceHeader
	if r, _, err := procGetAce.Call(uintptr(unsafe.Pointer(dacl)), uintptr(i),
		uintptr(unsafe.Pointer(&ace))); r == 0 {
		return heldEntry{}, fmt.Errorf("reading entry %d: %w", i, err)
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
		return heldEntry{}, fmt.Errorf("entry %d is of a kind that cannot be carried over (%d)", i, ace.kind)
	}
	return heldEntry{
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
	}, nil
}

// carryable walks a permission list entry by entry and answers whether
// every entry in it can be carried over, keeping none of them: rewriting
// a list wants the entries themselves, but the validation pass -- the
// reading pass that must stop a walk before anything has moved -- needs
// only the refusal, and building a list per object to throw it away made
// the pass allocate one slice per ACE for nothing.
func carryable(dacl *aclHeader) error {
	if dacl == nil {
		return nil
	}
	for i := uint16(0); i < dacl.count; i++ {
		if _, err := oneEntry(dacl, i); err != nil {
			return err
		}
	}
	return nil
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
//
// Unreadable is how the caller tells that answer from the other one. The two
// must not be printed alike -- see there.
func writableBy(path, account string) bool {
	held, err := heldBy(path, account, changing)
	if err != nil {
		return true
	}
	return held
}

// Unreadable reports that path's permission list cannot be read at all, so
// nothing can be said about who may write there.
//
// writableBy counts such a list as writable, which is the right way to fail
// and the wrong thing to print. The two findings are not the same, and the
// difference lands hardest where it alarms most: measured on an ordinary
// machine, `--audit` named two other people's profiles as writable by
// Everyone and by Users. Neither is. Their lists are unreadable precisely
// because they are closed, and this account may not look at them -- which the
// list then reported as the opposite of what it means.
func Unreadable(path string) bool {
	_, err := heldBy(path, sid.Everyone, changing)
	return err != nil
}

// readDACL asks Windows for path's permission list and nothing else about
// it.
func readDACL(path string) (*aclHeader, uintptr, error) {
	descriptorReads.Add(1)
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return nil, 0, callFailed("reading the permissions of", path, r)
	}
	return dacl, descriptor, nil
}

// holdsAny answers, from a list already read, whether account holds any
// of the wanted rights on the object the list belongs to.
//
// The list is read the way Windows reads it, in order, one right at a
// time: the first entry for this account that names a right still
// undecided settles that right, permission or refusal alike, and no
// entry after it revisits what was settled. A permission the list gives
// early therefore holds however many refusals follow it -- Windows' own
// check walks the entries in order and finishes the moment the rights it
// is still asking about are answered, so a refusal sitting behind an
// early permission is never reached about them. Subtracting every
// refusal from every permission read the list out of order, and --audit
// answered unwritable about directories a plain creation succeeds in:
// an explicit permission for Everyone with a refusal handed down from
// above sitting behind it is an ordinary shape, an object's own entries
// coming before the inherited ones.
//
// One account's reading is what this is, and no more than that: a real
// token also walks the account's other groups and stops early for them,
// and nothing here claims to combine group rights the way a token would.
//
// An inherit-only entry does not apply to the object this list sits on,
// only to what it hands down to; the copies the object received from
// above arrive without the mark and keep counting.
func holdsAny(held []heldEntry, account uintptr, wanted uint32) bool {
	const trusteeIsSID = 0
	var granted, undecided uint32 = 0, wanted
	for _, one := range held {
		if one.access.trustee.form != trusteeIsSID || one.access.inheritance&InheritOnly != 0 {
			continue
		}
		reached := one.access.permissions & undecided
		if reached == 0 {
			continue
		}
		if !sameSID(one.access.trustee.name, account) {
			continue
		}
		if one.access.mode == denyAccess {
			undecided &^= reached
		}
		if one.access.mode == grantAccess {
			granted |= reached
			undecided &^= reached
		}
	}
	return granted != 0
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
// An entry marked inherit-only is the one exception: it does not apply to the
// object it sits on, only to what it propagates down to, which is what
// InheritOnly says and what Windows' own entry inheritance rules say with it.
// Counting one made --audit answer both ways wrong: an inherit-only permission
// for Everyone reported the directory itself writable when the permission
// reaches only what is created under it, and an inherit-only refusal hiding
// beside a real permission reported it read-only when the refusal goes down
// and not inward. The copies an object receives from above keep counting,
// because they arrive effective, with the mark already taken off -- that is
// the fix that made --audit see inherited openness at all, and it must
// survive this one.
//
// The list itself is read in order, one right at a time, so a permission
// given early is not taken back by a refusal behind it -- holdsAny says
// how, and what one account's reading of a list is not.
func heldBy(path, account string, wanted uint32) (bool, error) {
	value, err := sid.Parse(account)
	if err != nil {
		return false, err
	}
	defer sid.Free(value)
	dacl, descriptor, err := readDACL(path)
	if err != nil {
		return false, err
	}
	defer w32.Free(descriptor)
	if dacl == nil {
		return true, nil // no permission list at all means everybody has everything
	}
	held, err := entriesOf(dacl)
	if err != nil {
		return false, fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	return holdsAny(held, value, wanted), nil
}

// A WritablePass is the two identities --audit asks about, resolved once
// for a pass over a tree, and the memory that keeps them answerable for
// exactly that long. Both identifiers are parsed from fixed text -- the
// same answer for every object on the walk -- so a parse per object bought
// nothing and left each of them on the system heap, which the collector
// does not manage, until the process ended.
type WritablePass struct {
	everyone uintptr // parsed at Begin, freed by End
	users    uintptr
}

// BeginWritable resolves, once, the two identities every sandbox carries
// through both of the access checks its token faces -- the list the audit
// walk exists to print.
func BeginWritable() (*WritablePass, error) {
	everyone, err := sid.Parse(sid.Everyone)
	if err != nil {
		return nil, err
	}
	users, err := sid.Parse(sid.Users)
	if err != nil {
		sid.Free(everyone)
		return nil, err
	}
	return &WritablePass{everyone: everyone, users: users}, nil
}

// End releases the pass: both identifiers go back to Windows. A pass is
// finished with once End has been called.
func (p *WritablePass) End() {
	sid.Free(p.everyone)
	sid.Free(p.users)
	p.everyone, p.users = 0, 0
}

// Writable answers, from one read of path's permission list, whether
// Everyone and BUILTIN\Users may change it -- the question the audit walk
// used to ask as two, plus a third for whether the list could be read at
// all. A list that cannot be read comes back as the error, not as an
// answer: what --audit prints for one is a different line, and a failure
// folded into an allow would claim definitively what nobody knows.
//
// The object itself is what this answers about: entries marked
// inherit-only pass it by (see holdsAny), and the copies it received from
// above count, which is what keeps an open directory above from looking
// closed.
func (p *WritablePass) Writable(path string) (everyone, users bool, err error) {
	dacl, descriptor, err := readDACL(path)
	if err != nil {
		return false, false, err
	}
	defer w32.Free(descriptor)
	if dacl == nil {
		return true, true, nil // no permission list at all means everybody has everything
	}
	held, err := entriesOf(dacl)
	if err != nil {
		return false, false, fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	return holdsAny(held, p.everyone, changing), holdsAny(held, p.users, changing), nil
}
