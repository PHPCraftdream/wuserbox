// Tests for the memo a revoke carries through a tree: the same trustee's
// identifier is classified once per revoke rather than once per entry on
// every object, and the classification ends with the revoke that made it.
//
// The shapes mirror reclaim_test.go: the synthetic world's one account is
// both the sandbox and the owner, which is exactly the pair the owner check
// compares, and what is measured runs unelevated. The tree tests use the
// same recovery the tree tests there do -- the walk root is itself an
// object the sandbox owns, so its own revoke caps it like any other, and a
// capped object owes its recovery to the privilege reclaimTree spends. An
// unelevated desk cannot spend it, which is where those tests end here.

package acl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// revokeSubject makes one file a revoke narrows: under root, owned by this
// account, and carrying a protected list of its own written in SDDL -- the
// only way to put exactly the entries a revoke meets on an object and
// nothing a directory above would hand down with them. The entries the
// revoke classifies are the ones the list names beyond this account's own.
func revokeSubject(t *testing.T, root, name, list string) string {
	t.Helper()
	file := filepath.Join(root, name)
	if err := os.WriteFile(file, []byte("the sandbox wrote this"), 0o644); err != nil {
		t.Fatal(err)
	}
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, file, owner)
	setSDDL(t, file, list)
	return file
}

// TestATakeBackAsksEachTrusteeOnceForTheWholeTree is the whole of the fix
// in one measurement. Four objects, each naming the same two unexpected
// trustees among its entries: the revoke asks Windows what each of those
// identifiers names once for the whole walk instead of once on every
// object, so four objects and eight eligible entries cost the two answers
// they are about. The tree root is walked like any other object -- it holds
// nothing but this account's own entry, which is the one kind of entry the
// revoke takes off without asking anything about it -- so it contributes
// nothing to the count, and its whole rewrite is the same one the
// single-object tests measure on the files below it.
func TestATakeBackAsksEachTrusteeOnceForTheWholeTree(t *testing.T) {
	root := reclaimRoot(t)
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, target, owner)
	setSDDL(t, target, `D:P(A;;FA;;;`+owner+`)`)

	files := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		files = append(files, revokeSubject(t, target, fmt.Sprintf("file-%d.txt", i),
			`D:P(A;;FA;;;`+owner+`)(A;;FA;;;`+sid.Everyone+`)(A;;FA;;;`+sid.Users+`)`))
	}

	before := sandboxNameLookups.Load()
	if err := TakeBack(target, IdentifierAlone(owner), nil); err != nil {
		t.Fatal(err)
	}
	if got := sandboxNameLookups.Load() - before; got != 2 {
		t.Fatalf("the revoke asked Windows for %d account names, want 2: four objects, two distinct trustees, one ask each", got)
	}
	for _, file := range files {
		if EveryoneWritable(file) {
			t.Errorf("the unexpected Everyone grant survived the revoke on %s", file)
		}
		if !holds(t, file, "OWNER RIGHTS", "(RX)") {
			t.Errorf("the revoke left the owner of %s uncapped", file)
		}
	}

	reclaimTree(t, root)
}

// TestATakeBackRemembersARefusedLookupOnlyAsItsNarrowing is the other half
// of the memo's contract. A lookup can refuse -- a stale entry, an entry
// naming nothing -- and the answer that refusal narrows with is remembered
// as that narrowing and nothing else: asked once for the whole tree, never
// repeated from it, and never turned into trust by a later object that
// repeats the same identifier. No account on any machine refuses on demand,
// so the package's seam stands in for the lookup: the current user's own
// identifier, which TakeBack resolves before the walk opens its first
// object, goes through to the real lookup underneath, and only the shared
// trustee's answer is refused.
func TestATakeBackRemembersARefusedLookupOnlyAsItsNarrowing(t *testing.T) {
	root := reclaimRoot(t)
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, target, owner)
	setSDDL(t, target, `D:P(A;;FA;;;`+owner+`)`)

	files := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		files = append(files, revokeSubject(t, target, fmt.Sprintf("file-%d.txt", i),
			`D:P(A;;FA;;;`+owner+`)(A;;FA;;;`+sid.Everyone+`)`))
	}

	real := accountNameOf
	everyone, err := sid.Parse(sid.Everyone)
	if err != nil {
		t.Fatal(err)
	}
	defer sid.Free(everyone)
	accountNameOf = func(value uintptr) (string, error) {
		if sameSID(value, everyone) {
			return "", errors.New("the lookup refused")
		}
		return real(value)
	}
	t.Cleanup(func() { accountNameOf = real })

	before := sandboxNameLookups.Load()
	if err := TakeBack(target, IdentifierAlone(owner), nil); err != nil {
		// A refused lookup narrows the entry it was asked about. It is not
		// a failure of the walk: the walk's own errors are the places it
		// cannot read, and this is neither.
		t.Fatalf("the revoke failed on a refused lookup: %v", err)
	}
	if got := sandboxNameLookups.Load() - before; got != 1 {
		t.Fatalf("the refused lookup was asked %d times, want 1: the refusal narrowed once, and every object after it was answered from that narrowing", got)
	}
	for _, file := range files {
		if EveryoneWritable(file) {
			t.Errorf("the refused lookup left the Everyone grant coming back as full control on %s", file)
		}
	}

	reclaimTree(t, root)
}

// TestATakeBackNarrowsAnUnresolvableTrustee is the referee's own answer:
// an identifier that is well formed and names nothing. The lookup runs, it
// answers that nothing maps to the identifier, and that narrows the entry
// exactly as any other refusal does -- once, and not repeated for a second
// copy of the same entry. What the entry is printed as afterwards is
// icacls' business; the absence of full control is what this measures.
func TestATakeBackNarrowsAnUnresolvableTrustee(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	probe := revokeSubject(t, root, "probe.txt", `D:P(A;;FA;;;`+owner+`)(A;;FA;;;`+unusedAccount+`)`)
	t.Cleanup(func() { reclaim(t, probe) })

	before := sandboxNameLookups.Load()
	if err := TakeBack(probe, IdentifierAlone(owner), nil); err != nil {
		t.Fatal(err)
	}
	if got := sandboxNameLookups.Load() - before; got != 1 {
		t.Fatalf("the unresolvable trustee was asked about %d times, want 1", got)
	}
	if holds(t, probe, unusedAccount, "(F)") {
		t.Fatal("the changing grant to an identifier that names nothing survived the revoke")
	}
	if !holds(t, probe, "OWNER RIGHTS", "(RX)") {
		t.Fatal("the revoke left the owner of the file uncapped")
	}
}

// TestTheTrusteeAnswersEndWithTheirOperation is operation-locality measured
// rather than assumed: the memo belongs to the revoke that made it, so a
// second revoke over a second tree asks the same question again instead of
// handing out the first one's answer. Two trees of one object each, the
// same broad grant on both -- a tree is one walk of one memo, and a walk of
// one object is a small tree. If the answers outlived their operation the
// second ask would be a hit, the counter would stay where it was, and this
// would fail.
func TestTheTrusteeAnswersEndWithTheirOperation(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	trees := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		tree := revokeSubject(t, root, fmt.Sprintf("tree-%d.txt", i),
			`D:P(A;;FA;;;`+owner+`)(A;;FA;;;`+sid.Everyone+`)`)
		if !EveryoneWritable(tree) {
			t.Fatalf("the broad Everyone grant was not present before TakeBack: %s", tree)
		}
		t.Cleanup(func() { reclaim(t, tree) })
		trees = append(trees, tree)
	}

	before := sandboxNameLookups.Load()
	for _, tree := range trees {
		if err := TakeBack(tree, IdentifierAlone(owner), nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := sandboxNameLookups.Load() - before; got != 2 {
		t.Fatalf("the two revokes asked Windows %d times between them, want 2: each operation asks its own question once, and the memo died with the operation that made it", got)
	}
	for _, tree := range trees {
		if EveryoneWritable(tree) {
			t.Errorf("the broad Everyone grant survived the revoke on %s", tree)
		}
	}
}

// TestARepeatAnswerAsksNothingAndAllocatesNothing is the hit path on its
// own: no object, no walk, one identifier already asked about. A repeat
// answer asks Windows nothing -- the counter does not move -- and reaches
// for the heap not once, because the key is an array rather than a slice
// and the lookup is a map access on it. Native asks and Go allocations are
// counted separately here, as they are everywhere in this package: one is a
// call into the account database, the other is the heap, and the memo is
// built to spend neither twice.
func TestARepeatAnswerAsksNothingAndAllocatesNothing(t *testing.T) {
	everyone, err := sid.Parse(sid.Everyone)
	if err != nil {
		t.Fatal(err)
	}
	defer sid.Free(everyone)

	// The key is content: the bytes of the identifier, eight of header and
	// one subauthority's worth for S-1-1-0, and a pointer there is nothing
	// at the end of is refused rather than keyed.
	key, ok := trusteeKey(everyone)
	if !ok {
		t.Fatal("a well-formed identifier could not be keyed")
	}
	if key.length != 12 {
		t.Fatalf("the key on %s is %d bytes, want 12", sid.Everyone, key.length)
	}
	if _, ok := trusteeKey(0); ok {
		t.Fatal("a nil pointer was keyed")
	}

	before := sandboxNameLookups.Load()
	answers := newTrusteeAnswers()
	if answers.sandboxGroup(everyone) {
		t.Fatal("Everyone is not one of the groups wuserbox creates, and was answered as if it were")
	}
	if got := sandboxNameLookups.Load() - before; got != 1 {
		t.Fatalf("the first answer asked Windows %d times, want 1", got)
	}

	// AllocsPerRun runs the closure once before it measures it, which is
	// why the measured runs are hits: the memo is already populated by the
	// ask above, exactly as a second object's repeat entry would find it.
	// Zero is not the bar: forming the key itself calls CopySid, and
	// //go:uintptrescapes forces the buffer that call fills to the heap on
	// every call, hit or miss -- reading the native bytes any other way is
	// the unsafe.Pointer misuse this package refuses to write. The bar a
	// hit must clear is the key's own unavoidable cost and nothing more:
	// the memo lookup after it must add no allocation of its own.
	keyAllocs := testing.AllocsPerRun(100, func() { _, _ = trusteeKey(everyone) })
	if allocs := testing.AllocsPerRun(100, func() { answers.sandboxGroup(everyone) }); allocs != keyAllocs {
		t.Errorf("a repeat answer allocated %v times per call, want exactly the key's own %v -- the memo lookup added its own", allocs, keyAllocs)
	}
	if got := sandboxNameLookups.Load() - before; got != 1 {
		t.Fatalf("a repeat answer asked Windows again: %d asks in total, want 1", got)
	}

	// The first ask does allocate -- the map is filled once, by the one
	// answer that had not been asked before -- which is the other half of
	// the zero above rather than a measurement of nothing.
	if allocs := testing.AllocsPerRun(1, func() {
		fresh := newTrusteeAnswers()
		fresh.sandboxGroup(everyone)
	}); allocs <= 0 {
		t.Errorf("the first ask allocated %v times, want some", allocs)
	}
}
