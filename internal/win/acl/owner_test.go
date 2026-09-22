// The owner of an object holds WRITE_DAC and READ_CONTROL implicitly, and the
// implicit grant is counted after every refusal the list makes. What wuserbox
// writes onto objects the sandbox owns so that the list it wrote is the last
// word, what stays working underneath it, and what the operator can still do
// afterwards. The full measurement is in the comment at the top of owner.go.

package acl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/quietexec"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// icacls runs icacls and hands back what it said. A refusal here is only
// evidence once the same command has been shown working, which is what
// rewriteWorks is for; the one answer that never means anything is a malformed
// identifier, which is refused outright.
func icacls(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	out, err := quietexec.Command("icacls", args...).CombinedOutput()
	if strings.Contains(string(out), "The security ID structure is invalid") {
		t.Fatalf("icacls %v: the identifier was not spelled the way icacls wants it:\n%s", args, out)
	}
	return out, err
}

// rewriteWorks shows an icacls grant working where every right is held, so a
// refusal of the same command below cannot be a syntax error.
func rewriteWorks(t *testing.T, path, account string) {
	t.Helper()
	if out, err := icacls(t, path, "/grant", "*"+account+":(F)"); err != nil {
		t.Fatalf("icacls /grant did not work on %s, where every right is held, so a refusal of it below proves nothing:\n%s", path, out)
	}
}

// rewriteRefused fails the test when the permission list of path can still be
// rewritten. why is the reason it must not be, and goes into the failure.
func rewriteRefused(t *testing.T, path, account, why string) {
	t.Helper()
	if out, err := icacls(t, path, "/grant", "*"+account+":(F)"); err == nil {
		t.Fatalf("the permission list of %s was rewritten: %s:\n%s", path, why, out)
	}
}

// reclaim removes a path the test may have locked itself out of, the way the
// operator recovers: through the parent directory. The parent is never capped
// by these tests -- its delete-child right is where recovery lives -- and
// where the machine's own directories hand the parent no entry to delete
// through, the parent's owner can still grant itself one, because ownership's
// WRITE_DAC there is untouched. A red run used to leave its subject behind,
// undeletable by ordinary cleanup, which is why this runs in a cleanup.
func reclaim(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		return // gone already: the test body got there first
	}
	if err := os.Remove(path); err == nil {
		return
	}
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Errorf("could not name this account to take %s back through its parent: %v", path, err)
		return
	}
	if out, err := icacls(t, filepath.Dir(path), "/grant", "*"+owner+":(DC)"); err != nil {
		t.Errorf("could not take %s back even through its parent:\n%s", path, out)
		return
	}
	if err := os.Remove(path); err != nil {
		t.Errorf("%s stayed behind after the parent's rights were restored: %v", path, err)
	}
}

// TestIsolateCapsWhatTheOwnerOfAFileHoldsImplicitly is the hole, measured:
// before the cap, the owner rewrote the list of a file whose own entries
// refuse the owner's account, because WRITE_DAC rides in with ownership
// whatever the list says.
func TestIsolateCapsWhatTheOwnerOfAFileHoldsImplicitly(t *testing.T) {
	root := t.TempDir() // never isolated: it is the recovery path, and this account holds every right there
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(root, "probe.txt")
	if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	guarded := filepath.Join(root, "guarded.txt")
	const original = "keep"
	if err := os.WriteFile(guarded, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, guarded, owner)
	t.Cleanup(func() { reclaim(t, guarded) })

	// Both probes shown working where every right is held, so the refusals
	// below cannot be a syntax error or a right this account never had.
	rewriteWorks(t, probe, owner)
	if out, err := icacls(t, probe, "/setowner", "*"+owner); err != nil {
		t.Fatalf("icacls /setowner did not work on %s, where every right is held:\n%s", probe, out)
	}

	// The list is written outright first, so that only these entries answer
	// below: on some desks the temporary directory hands every logged-on
	// account the write, and a machine-inherited entry would answer for the
	// refusals instead of the cap.
	//
	// The read-only grant's permission half, without its refusal entry: a
	// refusal naming the account this test runs as would refuse the very
	// recovery the test ends with -- measured, a file-level denial of delete
	// beats the parent's delete-child. The real refusal, naming the group and
	// not the person running the test, is what internal/e2e measures through
	// a real account.
	setSDDL(t, guarded, `D:P(A;;0x1200A9;;;`+owner+`)`)

	ro := []ACE{{Access: AccessReadExecute, Inheritance: InheritNone}}
	if err := Isolate(guarded, IdentifierAlone(owner), ro, InheritNone, nil); err != nil {
		t.Fatal(err)
	}

	rewriteRefused(t, guarded, owner,
		"the file's own entries give this account only reading, and the cap should hold the owner's implicit WRITE_DAC down")
	if out, err := icacls(t, guarded, "/setowner", "*"+owner); err == nil {
		t.Fatalf("ownership of %s was taken although the list refuses the account:\n%s", guarded, out)
	}
	if !holds(t, guarded, "OWNER RIGHTS", "(RX)") {
		t.Fatal("the owner-rights cap is not on the list")
	}

	// And nothing else moved: a refused rewrite does not half-apply.
	if err := os.WriteFile(guarded, []byte("tampered"), 0o644); err == nil {
		t.Fatal("a file whose entries give this account only reading was rewritten")
	}
	if got, err := os.ReadFile(guarded); err != nil || string(got) != original {
		t.Fatalf("the content of %s changed: %q (%v)", guarded, got, err)
	}

	// The recovery the operator keeps: deletion through the parent, a
	// directory this change never touched. Where the machine hands the parent
	// no delete-child -- this desk's temporary root hands only Modify, which
	// does not carry it -- the operator grants themselves one, which the
	// parent's own WRITE_DAC still allows, because the cap never lands on
	// it. Measured, without elevation, both shapes. Were this to fail, the
	// cap would be a one-way door.
	if out, err := icacls(t, root, "/grant", "*"+owner+":(DC)"); err != nil {
		t.Fatalf("the operator could not hold delete-child on the parent, which the cap never touches:\n%s", out)
	}
	if err := os.Remove(guarded); err != nil {
		t.Fatalf("a capped file could not be deleted through its untouched parent: %v", err)
	}
}

// TestTakingBackRepairsAnExtraOwnerRightsGrant guards the cap's fast path.
// One harmless RX entry must not make a second OWNER RIGHTS grant harmless.
func TestTakingBackRepairsAnExtraOwnerRightsGrant(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(root, "probe.txt")
	t.Cleanup(func() { reclaim(t, probe) })
	if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, probe, owner)
	setSDDL(t, probe, `D:P(A;;0x1200A9;;;S-1-3-4)(A;;0x40000;;;S-1-3-4)`)
	if err := TakeBack(probe, IdentifierAlone(owner), nil); err != nil {
		t.Fatal(err)
	}
	if !holds(t, probe, "OWNER RIGHTS", "(RX)") {
		t.Fatal("taking back an object with an extra owner-rights grant did not leave the cap")
	}
	rewriteRefused(t, probe, owner, "an extra OWNER RIGHTS grant left WRITE_DAC after TakeBack")
}

func TestAlreadyCappedRejectsAnUnexpectedTrustee(t *testing.T) {
	owner, err := sid.Parse(sid.OwnerRights)
	if err != nil {
		t.Fatal(err)
	}
	mark, err := sid.Parse(handDownMark)
	if err != nil {
		t.Fatal(err)
	}
	handSID, err := sid.Parse(unusedAccount)
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := sid.Parse(sid.Everyone)
	if err != nil {
		t.Fatal(err)
	}
	hand := []explicitAccess{entry(handSID, AccessReadExecute, InheritObjects, grantAccess)}
	base := []heldEntry{
		{access: hand[0]},
		{access: entry(owner, AccessReadExecute, InheritNone, grantAccess)},
		{access: entry(mark, AccessReadExecute, InheritNone, grantAccess)},
	}
	if !alreadyCapped(base, hand, owner, mark) {
		t.Fatal("the exact expected ACL was not accepted")
	}
	withExtra := append(append([]heldEntry(nil), base...), heldEntry{
		access: entry(everyone, 0x1F01FF, InheritNone, grantAccess),
	})
	if alreadyCapped(withExtra, hand, owner, mark) {
		t.Fatal("an unexpected broad trustee was accepted as an already-capped ACL")
	}
}

// TestIsolateRepairsAnExtraTrusteeOnAnAlreadyCappedOwnedChild guards the
// other fast-path hole: an object can carry every entry the sweep expects and
// an unrelated broad grant. The next sweep must publish the narrowed list,
// not accept that subset as finished.
func TestIsolateRepairsAnExtraTrusteeOnAnAlreadyCappedOwnedChild(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	handed := filepath.Join(root, "handed")
	if err := os.Mkdir(handed, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, handed, owner)

	// These are the entries the hand-down below will carry. The parent is
	// deliberately kept outside the already-capped children so cleanup still
	// has an untouched directory to go through.
	setSDDL(t, handed, `D:P(A;OICI;0x1301BF;;;`+owner+`)(A;OICI;0x1200A9;;;`+sid.Everyone+`)`)
	control := filepath.Join(handed, "control")
	extra := filepath.Join(handed, "extra")
	for _, path := range []string{control, extra} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		normalizeOwner(t, path, owner)
	}
	t.Cleanup(func() {
		reclaim(t, extra)
		reclaim(t, control)
		reclaim(t, handed)
	})

	// Both children already look capped. Only extra differs: Everyone has a
	// second, broad ACE that the old subset check ignored.
	base := `(A;OICI;0x1200A9;;;` + sid.Everyone + `)(A;OICI;0x1200A9;;;` + owner +
		`)(A;;0x1200A9;;;S-1-3-4)(A;;0x1200A9;;;S-1-0-0)`
	setSDDL(t, control, `D:P`+base)
	setSDDL(t, extra, `D:P`+base+`(A;;0x1F01FF;;;`+sid.Everyone+`)`)

	entries := []ACE{
		{Access: AccessReadExecute, Inheritance: InheritObjects | InheritContainers},
		{Access: 0x40, Inheritance: InheritNone}, // the operator's cleanup door
	}
	if err := Isolate(handed, IdentifierAlone(owner), entries, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if EveryoneWritable(extra) {
		t.Fatal("the extra Everyone grant survived Isolate's already-capped fast path")
	}
	if EveryoneWritable(control) {
		t.Fatal("the control child is writable by Everyone")
	}
	rewriteRefused(t, extra, owner,
		"the owner cap must block rewriting the child after the broad grant is removed")
}

// TestASweepCapsWhatTheSandboxOwnsInsideTheTree is the same hole one level
// down, where a production run actually meets it: the file was created inside
// the tree while the grant was writable, holds nothing of its own -- the
// grant's entries reach it inherited -- and it is the sweep that has to cap
// what its owner holds implicitly.
func TestASweepCapsWhatTheSandboxOwnsInsideTheTree(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(root, "probe.txt")
	if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	handed := filepath.Join(root, "handed")
	if err := os.Mkdir(handed, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, handed, owner)
	made := filepath.Join(handed, "made.txt")
	const original = "the sandbox wrote this"
	t.Cleanup(func() { reclaim(t, made); reclaim(t, handed) })
	// The tree is handed over in the shape a production run meets: held
	// writable, the file made inside it, the read-only grant landing on both
	// afterwards. Written outright first, so that only these entries answer
	// below -- the narrowing hands whatever it takes from a crowd entry to
	// the holder by name, and here the holder and the sandbox are the same
	// account, so a crowd write would come back through the handback and
	// answer for a refusal that should come from the cap.
	setSDDL(t, handed, `D:P(A;OICI;0x1301BF;;;`+owner+`)`)
	if err := os.WriteFile(made, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, made, owner)

	rewriteWorks(t, probe, owner)

	// Reading, and delete-what-is-inside. The second entry is the recovery
	// right: deleting a file asks for DELETE on the file or delete-child on
	// its parent, and this account holds that right on the directory the way
	// the operator holds it on the directory above a handed-over one. Without
	// it the capped directory's children could not be removed by anyone here,
	// and the test would end leaving what it cannot clean up.
	entries := []ACE{
		{Access: AccessReadExecute, Inheritance: InheritObjects | InheritContainers},
		{Access: 0x40, Inheritance: InheritNone}, // delete what is inside
	}
	if err := Isolate(handed, IdentifierAlone(owner), entries, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}

	rewriteRefused(t, made, owner,
		"the file was inside the tree when it was handed over, and the sweep should have capped its owner")
	rewriteRefused(t, handed, owner,
		"the directory handed over is owned by the account the entries name")
	if !holds(t, made, "OWNER RIGHTS", "(RX)") {
		t.Fatal("the sweep left the owner of a file inside the tree uncapped")
	}
	if !holds(t, handed, "OWNER RIGHTS", "(RX)") {
		t.Fatal("the directory handed over, owned by the same account, was not capped either")
	}
	if err := os.WriteFile(made, []byte("tampered"), 0o644); err == nil {
		t.Fatal("a file inside the handed-over tree was rewritten")
	}
	if got, err := os.ReadFile(made); err != nil || string(got) != original {
		t.Fatalf("the content of %s changed: %q (%v)", made, got, err)
	}

	// The recovery, both levels: the file through the delete-child right the
	// entries hold on the capped directory itself, the directory through its
	// untouched parent's -- granted there first where the machine hands no
	// such right to this account, which the parent's own WRITE_DAC allows,
	// because the cap never lands on the parent.
	if err := os.Remove(made); err != nil {
		t.Fatalf("the delete-child right held on the capped directory did not reach the file inside it: %v", err)
	}
	if out, err := icacls(t, root, "/grant", "*"+owner+":(DC)"); err != nil {
		t.Fatalf("the operator could not hold delete-child on the parent, which the cap never touches:\n%s", out)
	}
	if err := os.Remove(handed); err != nil {
		t.Fatalf("the untouched parent's delete-child right did not reach the capped directory: %v", err)
	}
}

// TestAHomeTopReapplyKeepsTheFilesTheSandboxMadeWritable is the HomeTop
// lifecycle: the deed lets the sandbox create a file directly in the granted
// directory and keeps it writable, and the grant is reapplied while the file
// is there. The first sweep's whole write used to carry the root's entries
// onto owned children as the root holds them, and an INHERIT_ONLY copy grants
// a file nothing -- the flag says the entry is about what the object hands
// down, and a file hands down nothing -- so the file the sandbox had been
// writing through real inheritance came out read-only for its owner after
// the reapply. The hand-down lands as each object would have held it, and
// the reapplied grant must leave the file writable, the deed's scope exactly
// where it was, and the door for files made afterwards open.
func TestAHomeTopReapplyKeepsTheFilesTheSandboxMadeWritable(t *testing.T) {
	root := t.TempDir()
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
	normalizeOwner(t, handed, owner)
	// The list is written outright first, so that only these entries answer
	// below: the machine's temporary directory hands every desk a different
	// crowd, and a crowd entry narrowed here would come back through the
	// handback naming this same account, answering for the write the deed is
	// supposed to grant.
	setSDDL(t, handed, `D:P(A;OICI;0x1301BF;;;`+owner+`)`)
	// What the reapply will meet, all of it predating the grant: sub
	// inherits the controlled list, and the files in and under it ride real
	// inheritance until the first sweep writes them whole. deeper.txt is a
	// generation past where the deed stops; sib.txt is outside handed
	// altogether, a neighbor the grant was never asked for.
	sub := filepath.Join(handed, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(sub, "nested.txt")
	if err := os.WriteFile(nested, []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}
	deeper := filepath.Join(sub, "deeper.txt")
	if err := os.WriteFile(deeper, []byte("deeper"), 0o644); err != nil {
		t.Fatal(err)
	}
	sib := filepath.Join(root, "sib.txt")
	if err := os.WriteFile(sib, []byte("sib"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{sub, nested, deeper, sib} {
		normalizeOwner(t, path, owner)
	}
	made := filepath.Join(handed, "made.txt")
	fresh := filepath.Join(handed, "fresh.txt")
	t.Cleanup(func() {
		reclaim(t, fresh)
		reclaim(t, made)
		reclaim(t, nested)
		reclaim(t, deeper)
		reclaim(t, sub)
		reclaim(t, handed)
	})

	// The deed as grant.HomeTop writes it, plus the operator's rights: one
	// account stands for both here, the same stand-in
	// TestASweepReachesWhatItWroteWhenTheGrantNarrows spells out, and
	// without them the cap on this directory would refuse the second apply
	// its own publish.
	const operators = 0x80000 | 0x40000 // take ownership, rewrite the list
	entries := []ACE{
		{Access: AccessCreateFiles, Inheritance: InheritNone},
		{Access: AccessModify, Inheritance: InheritObjects | InheritOnly | InheritNoPropagate},
		{Access: operators, Inheritance: InheritObjects | InheritContainers},
	}
	const reach = InheritObjects | InheritNoPropagate
	if err := Isolate(handed, IdentifierAlone(owner), entries, reach, nil); err != nil {
		t.Fatal(err)
	}

	// The deed: creating a file directly in the granted directory works, and
	// the grant stays in force for the file it let the sandbox make -- the
	// Modify rides real inheritance down onto the file as an effective
	// entry.
	if err := os.WriteFile(made, []byte("first"), 0o644); err != nil {
		t.Fatalf("the deed did not let the sandbox create a file in the granted directory: %v", err)
	}
	normalizeOwner(t, made, owner)
	if err := os.WriteFile(made, []byte("second"), 0o644); err != nil {
		t.Fatalf("the grant stopped working for the file it let the sandbox make: %v", err)
	}

	// The reapply the review is about: the same grant, run again over a tree
	// the first run already handed over.
	if err := Isolate(handed, IdentifierAlone(owner), entries, reach, nil); err != nil {
		t.Fatal(err)
	}

	// The regression: the reapply's whole write used to put the root's own
	// INHERIT_ONLY copy on this file, which grants a file nothing, leaving
	// the owner cap's reading alone where writing used to be. The hand-down
	// lands effective now, and the file keeps being written.
	if err := os.WriteFile(made, []byte("third"), 0o644); err != nil {
		t.Fatalf("the reapplied grant took the file back from the sandbox that made it: %v", err)
	}
	if got, err := os.ReadFile(made); err != nil || string(got) != "third" {
		t.Fatalf("the content of %s did not read back: %q (%v)", made, got, err)
	}
	// The cap survived the fix: the write above comes from the entry, not
	// from what ownership implies.
	if !holds(t, made, "OWNER RIGHTS", "(RX)") {
		t.Fatal("the owner-rights cap is not on the list of a file the sandbox made")
	}

	// The deed's scope, not widened: the directory directly under a home-top
	// root holds no modify of its own -- a copy made as the root holds it
	// would leave the root's inherit-only entry sitting there as an
	// inheritable one, handing the write down to files a level deeper than
	// the deed stops -- and a file a level deeper stays capped read-only.
	if holds(t, sub, name, "(M)") {
		t.Fatal("a directory directly under a home-top root holds a modify of its own")
	}
	if err := os.WriteFile(deeper, []byte("tampered"), 0o644); err == nil {
		t.Fatal("a file a level deeper than the deed stops was rewritten")
	}
	if holds(t, nested, name, "(M)") {
		t.Fatal("a file a level deeper than the deed stops holds a modify")
	}
	// Not extended past the tree either: nothing outside handed was swept or
	// capped.
	if holds(t, sib, "OWNER RIGHTS", "") {
		t.Fatal("a file outside the granted directory was swept or capped")
	}

	// And the deed still works for files made after the reapply: creating
	// one in the granted directory, and rewriting it too, its inherited
	// modify being the effective kind real inheritance lands on files.
	if err := os.WriteFile(fresh, []byte("fresh"), 0o644); err != nil {
		t.Fatalf("the reapplied grant lost the right to create files: %v", err)
	}
	if err := os.WriteFile(fresh, []byte("fresher"), 0o644); err != nil {
		t.Fatalf("the reapplied grant lost the write on a file made after it: %v", err)
	}
}

// TestAWritableGrantKeepsWorkingUnderTheCap is the grant half of the question.
// A writable grant gets the cap too -- an object the sandbox owns gets it
// whatever the grant says -- and nothing the grant is for stops working:
// rewriting and deleting come from the entry, not from ownership. What stops
// is the other way in: Modify never carried WRITE_DAC, and after the cap the
// owner's implicit one does not arrive either.
func TestAWritableGrantKeepsWorkingUnderTheCap(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	made := filepath.Join(root, "made.txt")
	if err := os.WriteFile(made, []byte("the sandbox wrote this"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, made, owner)

	if err := Isolate(made, IdentifierAlone(owner), []ACE{
		{Access: AccessModify, Inheritance: InheritNone},
	}, InheritNone, nil); err != nil {
		t.Fatal(err)
	}
	if !holds(t, made, "OWNER RIGHTS", "(RX)") {
		t.Fatal("the owner-rights cap is not on the list of an object handed over writable")
	}
	if err := os.WriteFile(made, []byte("rewritten"), 0o644); err != nil {
		t.Fatalf("a writable grant stopped working under the cap: %v", err)
	}
	if err := os.Remove(made); err != nil {
		t.Fatalf("a writable grant lost delete under the cap: %v", err)
	}
	rewriteRefused(t, made, owner,
		"Modify never carried WRITE_DAC and the cap holds the owner's implicit one down")
}

// TestIsolateLeavesAnObjectTheOperatorOwnsAlone is the common case, and the
// reason the cap is scoped the way it is: an owner-rights entry on an object
// the operator owns would cap the operator. Nothing here is the sandbox's, so
// no cap goes on, and the owner's implicit WRITE_DAC is where it always was.
func TestIsolateLeavesAnObjectTheOperatorOwnsAlone(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	handed := filepath.Join(root, "handed")
	if err := os.Mkdir(handed, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, handed, owner)
	made := filepath.Join(handed, "made.txt")
	if err := os.WriteFile(made, []byte("the operator wrote this"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Isolate(handed, IdentifierAlone(unusedAccount), []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if holds(t, handed, "OWNER RIGHTS", "") || holds(t, made, "OWNER RIGHTS", "") {
		t.Error("an owner-rights cap was written onto an object the operator owns")
	}
	rewriteWorks(t, handed, owner)
	rewriteWorks(t, made, owner)
}

// The identities the owner check compares against are resolved before
// anything is read or written, and the resolution fails closed: an account
// that cannot be resolved would otherwise come out as a shorter list of
// identities that quietly protects less. The cheapest case is an account
// that is not identifier text at all -- measured, ConvertStringSidToSidW
// answers 1337 ERROR_INVALID_SID for a plain account name.
func TestIsolateRefusesAnAccountItCannotResolve(t *testing.T) {
	if err := Isolate(t.TempDir(), SandboxGroup("nobody in particular"), []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err == nil {
		t.Fatal("a grant went out under an account that could not be resolved")
	}
}

// TestASweepReachesWhatItWroteWhenTheGrantNarrows is the ordinary sequence,
// --grant, work, --ro on the same directory: whatever the writable sweep
// wrote, the read-only sweep replaces. The first form of the skip compared
// against nothing, and a file kept the writable grant's write through the
// read-only narrowing that followed it -- measured -- and kept a refusal
// standing through every widening after it.
//
// The operator's rights ride along on the same identifier here, because the
// synthetic world has one account; a production run separates them, and the
// refusal that binds the account which owns the object -- as against the
// operator, who holds the right to change their mind -- is what the tests
// beside this one and the real-account test in internal/e2e pin. What this
// one pins is the hand-down: the entries one grant wrote are not the entries
// the next one finds.
func TestASweepReachesWhatItWroteWhenTheGrantNarrows(t *testing.T) {
	root := t.TempDir()
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
	// The operator's WRITE_DAC and WRITE_OWNER, named to the account itself
	// because here the operator and the owner are one account, and
	// inheritable because a production operator's entries ride the hand-down
	// the same way: they are what lets every later sweep rewrite what it
	// wrote, and what the narrowing hands down along with its own entries.
	const operators = 0x80000 | 0x40000 // take ownership, rewrite the list
	writable := []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
		{Access: operators, Inheritance: InheritObjects | InheritContainers},
	}
	readable := []ACE{
		{Access: AccessReadExecute, Inheritance: InheritObjects | InheritContainers},
		{Access: 0x40, Inheritance: InheritNone}, // delete what is inside
		{Access: operators, Inheritance: InheritObjects | InheritContainers},
	}
	setSDDL(t, handed, `D:P(A;OICI;0x1301BF;;;`+owner+`)`)
	made := filepath.Join(handed, "made.txt")
	const written = "rewritten under the writable grant"
	if err := os.WriteFile(made, []byte("the sandbox wrote this"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reclaim(t, made); reclaim(t, handed) })

	if err := Isolate(handed, IdentifierAlone(owner), writable, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(made, []byte(written), 0o644); err != nil {
		t.Fatalf("a writable grant stopped working: %v", err)
	}

	if err := Isolate(handed, IdentifierAlone(owner), readable, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if holds(t, made, name, "(M)") {
		t.Fatal("a file kept the writable grant's Modify through the read-only narrowing that followed it")
	}
	if !holds(t, made, name, "(RX)") {
		t.Fatal("the read-only narrowing's own entries did not reach the file the first sweep had written")
	}
	if err := os.WriteFile(made, []byte("tampered"), 0o644); err == nil {
		t.Fatal("a file under a read-only grant was rewritten")
	}
	if got, err := os.ReadFile(made); err != nil || string(got) != written {
		t.Fatalf("the content of %s changed under the narrowing: %q (%v)", made, got, err)
	}

	// And widened again, it is writable again: the rewrite runs whichever way
	// the grant moves, so the narrowing is not a door that only opens one
	// way.
	if err := Isolate(handed, IdentifierAlone(owner), writable, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(made, []byte("writable again"), 0o644); err != nil {
		t.Fatalf("a grant widened back did not make its own files writable again: %v", err)
	}
}
