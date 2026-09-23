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
	"sync/atomic"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// TakeBack takes the identity's entries off root and everything under it, and caps
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
func TakeBack(root string, subject Identity, pinned []string) error {
	sandbox, err := identitiesFor(subject)
	if err != nil {
		return err
	}
	defer sandbox.End()
	if err := sandbox.cast(); err != nil {
		return err
	}
	spared, err := makePinnedPaths(pinned)
	if err != nil {
		return err
	}
	spared, err = spared.relevant(root)
	if err != nil {
		return err
	}
	if len(spared.keys) != 0 {
		if err := spared.prepare(root); err != nil {
			return err
		}
	}
	// One memo for the whole walk: a tree's entries name the same few
	// trustees from object to object, and the question each one answers is
	// answered once here instead of once on every object that repeats it.
	answers := newTrusteeAnswers()
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
		kept, err := spared.contains(name)
		if err != nil {
			return err
		}
		if kept {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		return takeBack(name, sandbox, answers)
	})
}

// takeBack is one object's share of taking a grant back: the account's own
// entries go, and an object the sandbox's account owns has the cap written
// onto it, once, in the same update -- measured on the narrowing side, once
// the cap has landed the owner can no longer edit the list at all, so a cap
// that arrives late arrives never (owner.go).
func takeBack(path string, sandbox *identities, answers *trusteeAnswers) error {
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo|ownerInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return callFailed("reading the permissions of", path, r)
	}
	defer w32.Free(descriptor)

	held, err := entriesOf(dacl)
	if err != nil {
		return fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	owned := ownedByTheSandbox(ownerOf(descriptor), sandbox.values)
	var clear []explicitAccess
	for _, one := range held {
		if one.inherited || !matchesSandboxIdentity(one.access.trustee.name, sandbox.values) {
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
		carried, _ := carryRevokeEntries(held, sandbox.values, answers, sandbox.holder, sandbox.system, sandbox.administrators)
		return writeWhole(path, carried, nil, nil, sandbox.ownerRights, sandbox.mark)
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
		carried, _ := carryRevokeEntries(held, sandbox.values, answers, sandbox.holder, sandbox.system, sandbox.administrators)
		return writeWhole(path, append(clear, carried...), nil, nil, sandbox.ownerRights, sandbox.mark)
	}
	if capPresent(held, sandbox.ownerRights) {
		// A cap by itself is not proof that the list is safe: an earlier
		// revoke could have accepted an owner-rights entry while an
		// unexpected explicit broad grant stood beside it. Normalize that
		// list before treating the fast path as finished.
		carried, changed := carryRevokeEntries(held, sandbox.values, answers, sandbox.holder, sandbox.system, sandbox.administrators)
		if !changed {
			return nil
		}
		return writeWhole(path, carried, nil, nil, sandbox.ownerRights, sandbox.mark)
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
	return writeWhole(path, nil, nil, nil, sandbox.ownerRights, sandbox.mark)
}

// revokeCarry decides which explicit permissions may survive a revoke on an
// object owned by the sandbox. Operator recovery and the machine principals
// are part of the product's ACL contract. A grant to another wuserbox group
// is an independent sandbox grant, so it remains intact too. Every other
// changing grant is narrowed to its non-changing rights; otherwise a sandbox
// could pre-write Everyone:Full Control and keep changing the object after
// its own account entry and owner rights had been removed.
func revokeCarry(access explicitAccess, answers *trusteeAnswers, operator, system, administrators uintptr) (explicitAccess, bool) {
	if access.mode != grantAccess || access.permissions&changing == 0 {
		return access, true
	}
	if sameSID(access.trustee.name, operator) || sameSID(access.trustee.name, system) ||
		sameSID(access.trustee.name, administrators) || answers.sandboxGroup(access.trustee.name) {
		return access, true
	}
	access.permissions &^= changing
	return access, access.permissions != 0
}

// carryRevokeEntries keeps every entry that is not one of the sandbox's
// identities while applying the revoke policy to every changing grant. An
// inherited entry is included deliberately: the inherited branch writes a
// whole, protected list, so dropping trusted inherited access there would
// silently remove recovery and system rights. changed reports whether any
// entry was removed or narrowed, which is what invalidates the already-capped
// fast path.
func carryRevokeEntries(held []heldEntry, sandbox []uintptr, answers *trusteeAnswers, operator, system, administrators uintptr) ([]explicitAccess, bool) {
	var carried []explicitAccess
	changed := false
	for _, one := range held {
		if matchesSandboxIdentity(one.access.trustee.name, sandbox) {
			continue
		}
		access, keep := revokeCarry(one.access, answers, operator, system, administrators)
		if access.permissions != one.access.permissions || !keep {
			changed = true
		}
		if keep {
			carried = append(carried, access)
		}
	}
	return carried, changed
}

// A counter, for the close test of a revoke over a tree and anyone
// diagnosing one: how many account-name lookups the revoke's classification
// paid for. Each one used to be asked once per eligible entry on every
// object, which is O(N·A) lookups about U distinct trustees, and each ask
// is a sizing call, two buffers and a second call into the account
// database. What the memo below asks once, this counts once; a hit is
// answered out of the memo and costs nothing, so it is counted as nothing.
var sandboxNameLookups atomic.Int64

// maxSIDSubAuthorities is the most subauthorities an identifier carries.
// A shape claiming more than that is either malformed or was never an
// identifier, and either way there are no bytes to key on.
const maxSIDSubAuthorities = 15

// sidHeaderBytes is the front every identifier carries before its
// subauthorities: the revision, the subauthority count, and the six bytes
// of authority.
const sidHeaderBytes = 8

// sidKey carries the bytes that make up one identifier, copied out of the
// descriptor they were read from, as a map key.
//
// It is keyed by CONTENT, never by the pointer the entry stood on: the
// descriptor is freed the moment its object is written, and the heap hands
// the same address to the next one, so an address key would answer one
// identifier's question with another's answer -- the last object's trustee
// standing in for this one's, and the answer being one of trust, that is a
// door left open rather than a question asked. A SID is at most
// sidHeaderBytes + 4*maxSIDSubAuthorities bytes.
type sidKey struct {
	length int
	value  [sidHeaderBytes + 4*maxSIDSubAuthorities]byte
}

// trusteeKey copies the identifier at value into a key, refusing a pointer
// there is nothing to read from: a nil one, or a shape claiming more
// subauthorities than an identifier can hold. The caller then asks and
// answers without the memo rather than trust bytes it could not read.
//
// The copy goes through CopySid rather than through the memory at the
// pointer: the pointer is a raw address rather than a Go pointer, and
// reaching the memory behind one of those directly is the thing the unsafe
// rules refuse to name -- vet calls every such conversion a possible
// misuse, so none is written here. CopySid reads the same bytes into the
// scratch the memo already owns in one call, and refuses a shape too large
// for that buffer, which is the same refusal this makes.
var procCopySid = w32.Advapi32.NewProc("CopySid")

func (t *trusteeAnswers) trusteeKey(value uintptr) (sidKey, bool) {
	if value == 0 {
		return sidKey{}, false
	}
	if r, _, _ := procCopySid.Call(sidHeaderBytes+4*maxSIDSubAuthorities,
		uintptr(unsafe.Pointer(&t.scratch[0])), value); r == 0 {
		return sidKey{}, false
	}
	count := int(t.scratch[1])
	if count > maxSIDSubAuthorities {
		return sidKey{}, false
	}
	var key sidKey
	key.length = sidHeaderBytes + 4*count
	copy(key.value[:], t.scratch[:key.length])
	return key, true
}

// trusteeAnswers remembers, for the length of one revoke, how each trustee's
// identifier classified -- the question asked once per distinct identifier
// instead of once per entry on every object. N objects carrying A eligible
// entries each used to ask O(N·A) questions about at most U different
// trustees; this is what makes that U.
//
// The memo is the operation's, the way identities is: TakeBack creates it,
// and it is unreachable by the time TakeBack returns. An answer that
// outlived its operation would answer the next operation's question, and
// the next operation's descriptor hands the same addresses to different
// trustees -- which is exactly what keying on content rather than on the
// pointer refuses. One operation is one goroutine (filepath.WalkDir), so
// nothing here is locked.
type trusteeAnswers struct {
	// ask is how a classification is settled, and is always accountNameOf
	// in production: the seam every other account-name lookup in this
	// package goes through, so a lookup that refuses can be stood in for
	// in a test the way it already can everywhere else.
	ask     func(uintptr) (string, error)
	decided map[sidKey]bool

	// scratch is the buffer CopySid fills while a key is formed, and it
	// lives on the memo because //go:uintptrescapes forces whatever buffer
	// CopySid fills to escape: a buffer born with each ask went to the heap
	// on every ask, hit or miss, where one the memo already owns is paid
	// for once when the memo is made and reused ask after ask. Reuse is
	// race-free because one memo belongs to one TakeBack, and one TakeBack
	// is one goroutine -- filepath.WalkDir walks synchronously -- so no two
	// asks are ever in flight at once. What the map sees stays safe, too:
	// the key is copied out of the scratch before trusteeKey returns, so
	// nothing in the map references the scratch when the next ask
	// overwrites it.
	scratch [sidHeaderBytes + 4*maxSIDSubAuthorities]byte
}

func newTrusteeAnswers() *trusteeAnswers {
	return &trusteeAnswers{ask: accountNameOf, decided: make(map[sidKey]bool)}
}

// sandboxGroup answers the same question the unmemoized call did: does this
// identifier name one of the groups wuserbox creates? Resolving an
// identifier can fail for a stale or synthetic entry; failing closed
// narrows that entry rather than treating an unknown principal as trusted.
// What changed is only how often the question is asked -- once per distinct
// identifier for the whole revoke, not once per entry on every object.
//
// A refused lookup is remembered as what it cost -- the narrowing (false)
// -- and never as trust: a refusal says nothing good about the identifier,
// so the answer it narrows with is the answer the next object gets, and a
// hit can narrow, never broaden, because nothing enters the map that a real
// lookup did not say. An identifier whose bytes cannot be read as an
// identifier's shape is asked and answered every time, uncached: it is
// asked rarely enough for that to cost nothing, and its absence from the
// map is the honest record of a question this could not read.
func (t *trusteeAnswers) sandboxGroup(value uintptr) bool {
	key, keyed := t.trusteeKey(value)
	if keyed {
		if decided, hit := t.decided[key]; hit {
			return decided
		}
	}
	sandboxNameLookups.Add(1)
	trusted := false
	if name, err := t.ask(value); err == nil && group.IsSandbox(name) {
		trusted = true
	}
	if keyed {
		t.decided[key] = trusted
	}
	return trusted
}
