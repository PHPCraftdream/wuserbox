// What spares an object the sandbox owns is the record, never the shape of
// the object's permission list. The sandbox that owns an object could have
// written that list itself while it held every right -- emptying its own
// list is a right ownership implies -- so a list that is its own is no
// evidence of a seal the operator chose, and reading it as one left the
// sandbox's own entries and its implicit WRITE_DAC standing on exactly the
// objects the sandbox chose. Pinned here: the paths the record holds are
// what is spared, a pinned directory with its whole subtree, what the sweep
// reaches once the shape of a list is no longer believed, and the identity
// list the owner check compares against at its own level -- it fails closed,
// and an account that names no group is the whole of its own list.
// Everything runs unelevated, because the synthetic world's one account is
// both the sandbox and the owner, which is exactly the pair the owner check
// compares.

package acl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

func TestPinnedPathsKeepOnlyDescendantsOfTheCurrentRoot(t *testing.T) {
	root := t.TempDir()
	rootOnly, err := makePinnedPaths([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	rootOnly, err = rootOnly.relevant(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rootOnly.keys) != 0 || len(rootOnly.resolved) != 0 {
		t.Fatalf("root-only keep-list was not removed before snapshot: keys=%d resolved=%d",
			len(rootOnly.keys), len(rootOnly.resolved))
	}

	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	set, err := makePinnedPaths([]string{root, child, outside})
	if err != nil {
		t.Fatal(err)
	}
	relevant, err := set.relevant(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(relevant.keys) != 1 {
		t.Fatalf("relevant keep-list has %d entries, want only the descendant", len(relevant.keys))
	}
	if len(relevant.resolved) != 0 {
		t.Fatal("filtering the keep-list performed a tree snapshot")
	}
	kept, err := relevant.contains(child)
	if err != nil || !kept {
		t.Fatalf("the real descendant was not retained: kept=%v err=%v", kept, err)
	}
	if kept, err := relevant.contains(root); err != nil || kept {
		t.Fatalf("the current root was retained in the keep-list: kept=%v err=%v", kept, err)
	}
}

func TestPinnedPathsFailClosedWhenRelevanceCannotBeResolved(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	set, err := makePinnedPaths([]string{missing})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.relevant(root); err == nil {
		t.Fatal("an unresolved pinned path was silently omitted")
	}
}

// TestASealedObjectTheRecordHoldsIsLeftAlone replaces the old sealed-object
// test, which pinned the opposite of this fix: that an object whose list is
// its own is spared. The list can be the sandbox's own work, so what spares
// an object now is the record, and the record alone.
func TestASealedObjectTheRecordHoldsIsLeftAlone(t *testing.T) {
	root := t.TempDir() // never isolated: it is the recovery path, and this account holds every right there
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	// icacls prints resolved account names, not identifier text, so what the
	// holds helper searches for is the name of this account.
	pointer, err := sid.Parse(owner)
	if err != nil {
		t.Fatal(err)
	}
	name, err := sid.Name(pointer)
	if err != nil {
		t.Fatal(err)
	}
	handed := filepath.Join(root, "handed")
	if err := os.Mkdir(handed, 0o755); err != nil {
		t.Fatal(err)
	}
	sealed := filepath.Join(handed, "sealed")
	if err := os.Mkdir(sealed, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, sealed, owner)
	kept := filepath.Join(sealed, "kept.txt")
	if err := os.WriteFile(kept, []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, kept, owner)
	sealedFile := filepath.Join(handed, "sealed.txt")
	if err := os.WriteFile(sealedFile, []byte("sealed"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, sealedFile, owner)
	plain := filepath.Join(handed, "plain.txt")
	if err := os.WriteFile(plain, []byte("plain"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, plain, owner)
	// Sealed against everybody but its owner, who holds every right: the
	// shape of a list that is its own and nothing inherited under it -- and
	// the shape the sandbox itself can write while it owns the object.
	setSDDL(t, sealed, `D:P(A;OICI;FA;;;`+owner+`)`)
	setSDDL(t, sealedFile, `D:P(A;;FA;;;`+owner+`)`)
	t.Cleanup(func() {
		reclaim(t, kept)
		reclaim(t, plain)
		reclaim(t, sealed)
		reclaim(t, sealedFile)
		reclaim(t, handed)
	})

	// Reading, and delete-what-is-inside handed down. The second entry rides
	// the hand-down on purpose, so every object this grant caps keeps the
	// delete path the tests end with; a pinned directory is skipped with its
	// whole subtree, so kept rides along untouched inside it.
	if err := Isolate(handed, owner, []ACE{
		{Access: AccessReadExecute, Inheritance: InheritObjects | InheritContainers},
		{Access: 0x40, Inheritance: InheritObjects | InheritContainers}, // delete what is inside, handed down
	}, InheritObjects|InheritContainers, []string{sealed, sealedFile}); err != nil {
		t.Fatal(err)
	}

	// What the record holds is what stays as it was: no hand-down, and no
	// cap -- the pair was recorded as granted in their own right, and no
	// list the sandbox could have written stands in for that decision.
	for _, path := range []string{sealed, sealedFile} {
		if !holds(t, path, name, "(F)") {
			t.Errorf("%s lost what it held when the tree above it was handed over", path)
		}
		if holds(t, path, "OWNER RIGHTS", "") {
			t.Errorf("an owner-rights cap was written onto an object the record pins")
		}
	}
	if err := os.WriteFile(sealedFile, []byte("still mine"), 0o644); err != nil {
		t.Errorf("the owner of a sealed object lost access to it: %v", err)
	}
	// The negative control, and the point of the whole test: an object in
	// the same tree, holding nothing of its own and no mark, was capped --
	// so it is the record that spared the sealed pair, not the shape of
	// their lists.
	if !holds(t, plain, "OWNER RIGHTS", "(RX)") {
		t.Fatal("an object in the same tree, holding nothing of its own and no mark, was not capped -- " +
			"so a list's shape, not the record, would be what spared the sealed pair")
	}
}

// TestWithoutTheRecordASweepReachesWhatTheSandboxSealed is the same tree
// without the record: what used to spare the sealed pair was the shape of
// their lists, and once only the record can spare, the sweep reaches both of
// them and what is inside them -- the walk descends into a capped directory
// now, and finds kept there.
func TestWithoutTheRecordASweepReachesWhatTheSandboxSealed(t *testing.T) {
	root, err := os.MkdirTemp("", "wub-pinned-no-record-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	pointer, err := sid.Parse(owner)
	if err != nil {
		t.Fatal(err)
	}
	name, err := sid.Name(pointer)
	if err != nil {
		t.Fatal(err)
	}
	handed := filepath.Join(root, "handed")
	if err := os.Mkdir(handed, 0o755); err != nil {
		t.Fatal(err)
	}
	sealed := filepath.Join(handed, "sealed")
	if err := os.Mkdir(sealed, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, sealed, owner)
	kept := filepath.Join(sealed, "kept.txt")
	if err := os.WriteFile(kept, []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, kept, owner)
	sealedFile := filepath.Join(handed, "sealed.txt")
	if err := os.WriteFile(sealedFile, []byte("sealed"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, sealedFile, owner)
	// Keep the operator's own Full Control out of the hand-down after the
	// fixture tree exists. The sandbox identity is the current account in this
	// synthetic test, so an operator ACE would be mistaken for a permission
	// the cap must preserve.
	setSDDL(t, handed, `D:P(A;OICI;0x1200E9;;;`+owner+`)(A;OICI;0x1301BF;;;`+unusedAccount+`)`)
	setSDDL(t, sealed, `D:P(A;OICI;FA;;;`+owner+`)`)
	setSDDL(t, sealedFile, `D:P(A;;FA;;;`+owner+`)`)
	// The tree itself is intentionally capped to the current synthetic owner;
	// on an administrator runner that can leave the final directory unreadable
	// to ordinary cleanup. The assertions below are the security result, so
	// cleanup is best-effort for this temporary tree.
	t.Cleanup(func() {
		_ = os.RemoveAll(handed)
	})

	if err := Isolate(handed, owner, []ACE{
		{Access: AccessReadExecute, Inheritance: InheritObjects | InheritContainers},
		{Access: 0x40, Inheritance: InheritObjects | InheritContainers}, // delete what is inside, handed down
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}

	// All three end capped, each by its own road: sealed and sealedFile held
	// lists of their own and are written whole with the hand-down in it,
	// while kept still heard from above -- its parent was sealed, and its
	// list is what sealed handed down before the rewrite.
	//
	// The delete-child right riding the hand-down is what this test ends
	// with: once the cap has landed nobody holds WRITE_DAC on any of these
	// objects any more, so the inherited entry is the delete path.
	for _, path := range []string{sealed, kept, sealedFile} {
		if !holds(t, path, "OWNER RIGHTS", "(RX)") {
			t.Errorf("%s was not capped when the tree above it was handed over", path)
		}
		if holds(t, path, name, "(F)") {
			t.Errorf("%s kept the full control its own list granted it through the narrowing", path)
		}
	}
	if err := os.WriteFile(sealedFile, []byte("tampered"), 0o644); err == nil {
		t.Fatal("a file the sandbox re-permissioned while it owned it kept the write through the narrowing")
	}
	if got, err := os.ReadFile(sealedFile); err != nil || string(got) != "sealed" {
		t.Fatalf("the content of %s changed: %q (%v)", sealedFile, got, err)
	}

	// And the recovery lives, because the hand-down carries delete-child:
	// the file out of the capped directory, then the directory through the
	// capped handed -- neither holds delete of its own any more. The
	// reclaims in the cleanup stay as the safety net; these removes are the
	// assertion that the way out is still there.
	if err := os.Remove(kept); err != nil {
		t.Fatalf("the delete-child right held on the capped directory did not reach the file inside it: %v", err)
	}
	if err := os.Remove(sealed); err != nil {
		t.Fatalf("the delete-child right held on the capped directory above did not reach the capped directory itself: %v", err)
	}
}

// TestPinnedEntriesUseFilesystemIdentityNotUnicodeFold keeps a pinned K
// directory separate from its filesystem-distinct Kelvin-sign sibling. Both
// are own lists, so only the record can spare one; Isolate and TakeBack must
// preserve that exact entry and cap the other one.
func TestPinnedEntriesUseFilesystemIdentityNotUnicodeFold(t *testing.T) {
	root := reclaimRoot(t)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, target, owner)
	setSDDL(t, target, `D:P(A;OICI;0x1301BF;;;`+owner+`)`)

	pinned := filepath.Join(target, "K")
	other := filepath.Join(target, "\u212A")
	if err := os.Mkdir(pinned, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Skipf("this volume does not distinguish K and Kelvin sign: %v", err)
	}
	first, err := os.Stat(pinned)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(first, second) {
		t.Skip("the volume reports K and Kelvin sign as the same directory")
	}

	pinnedFile := filepath.Join(pinned, "kept.txt")
	otherFile := filepath.Join(other, "capped.txt")
	for _, path := range []string{pinnedFile, otherFile} {
		if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}
		normalizeOwner(t, path, owner)
	}
	// Protected own lists model directories independently granted by the
	// operator. Unicode folding must not make the second one look pinned.
	setSDDL(t, pinned, `D:P(A;OICI;FA;;;`+owner+`)`)
	setSDDL(t, pinnedFile, `D:P(A;;FA;;;`+owner+`)`)
	setSDDL(t, other, `D:P(A;OICI;FA;;;`+owner+`)`)
	setSDDL(t, otherFile, `D:P(A;;FA;;;`+owner+`)`)

	entries := []ACE{
		{Access: AccessReadExecute, Inheritance: InheritObjects | InheritContainers},
		{Access: 0x40, Inheritance: InheritObjects | InheritContainers},
	}
	if err := Isolate(target, owner, entries, InheritObjects|InheritContainers, []string{pinned}); err != nil {
		t.Fatal(err)
	}
	rewriteWorks(t, pinnedFile, owner)
	rewriteRefused(t, otherFile, owner,
		"the filesystem-distinct Kelvin-sign entry was mistaken for the pinned K entry")

	// Repeat the same pair through the revoke path. Isolate has already capped
	// target, so a separate writable root models the operator taking a grant
	// back while its owner still has the write-DAC needed for that one update.
	revoked := filepath.Join(root, "revoked")
	if err := os.Mkdir(revoked, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, revoked, owner)
	setSDDL(t, revoked, `D:P(A;OICI;0x1301BF;;;`+owner+`)`)
	revokedPinned := filepath.Join(revoked, "K")
	revokedOther := filepath.Join(revoked, "\u212A")
	if err := os.Mkdir(revokedPinned, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(revokedOther, 0o755); err != nil {
		t.Skipf("this volume does not distinguish K and Kelvin sign: %v", err)
	}
	for _, path := range []string{revokedPinned, revokedOther} {
		normalizeOwner(t, path, owner)
		setSDDL(t, path, `D:P(A;OICI;FA;;;`+owner+`)`)
	}
	revokedPinnedFile := filepath.Join(revokedPinned, "kept.txt")
	revokedOtherFile := filepath.Join(revokedOther, "capped.txt")
	for _, path := range []string{revokedPinnedFile, revokedOtherFile} {
		if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}
		normalizeOwner(t, path, owner)
		setSDDL(t, path, `D:P(A;;FA;;;`+owner+`)`)
	}
	if err := TakeBack(revoked, owner, []string{revokedPinned}); err != nil {
		t.Fatal(err)
	}
	rewriteWorks(t, revokedPinnedFile, owner)
	rewriteRefused(t, revokedOtherFile, owner,
		"revoke spared the filesystem-distinct Kelvin-sign entry with the pinned K entry")
}

// The identity list the owner check compares against fails closed. The
// cheapest account that cannot be resolved is one that is not identifier
// text at all.
func TestTheIdentitiesFailClosedWhenTheAccountIsNotSIDText(t *testing.T) {
	identities, err := sandboxIdentities("nobody in particular")
	if err == nil {
		t.Fatal("an account that is not identifier text resolved to something")
	}
	if len(identities) != 0 {
		t.Errorf("an unresolvable account came out as a list of %d identities", len(identities))
	}
}

// TestTheIdentitiesOfAnAccountThatNamesNoGroupAreItself: a plain account and
// a synthetic identifier name no local group, measured --
// NetLocalGroupGetMembers answers 1376 ERROR_NO_SUCH_ALIAS for the bare name
// of a plain account and 2220 NERR_GroupNotFound for a qualified one -- and
// the one identifier is the whole answer. The fail-closed half is covered by
// the test above and by the real-group test in internal/e2e.
func TestTheIdentitiesOfAnAccountThatNamesNoGroupAreItself(t *testing.T) {
	user, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{unusedAccount, user} {
		pointer, err := sid.Parse(account)
		if err != nil {
			t.Fatal(err)
		}
		identities, err := sandboxIdentities(account)
		if err != nil {
			t.Fatalf("%s: %v", account, err)
		}
		if len(identities) != 1 {
			t.Fatalf("%s came out as a list of %d identities, want the account alone", account, len(identities))
		}
		if !sameSID(identities[0], pointer) {
			t.Errorf("the one identity held for %s is not the account itself", account)
		}
	}
}
