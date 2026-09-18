// The owner of an object holds WRITE_DAC and READ_CONTROL implicitly, and the
// implicit grant is counted after every refusal the list makes. What wuserbox
// writes onto objects the sandbox owns so that the list it wrote is the last
// word, what stays working underneath it, and what the operator can still do
// afterwards. The full measurement is in the comment at the top of owner.go.

package acl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// icacls runs icacls and hands back what it said. A refusal here is only
// evidence once the same command has been shown working, which is what
// rewriteWorks is for; the one answer that never means anything is a malformed
// identifier, which is refused outright.
func icacls(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	out, err := exec.Command("icacls", args...).CombinedOutput()
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
	if err := Isolate(guarded, owner, ro, InheritNone, nil); err != nil {
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
	if err := Isolate(handed, owner, entries, InheritObjects|InheritContainers, nil); err != nil {
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

	if err := Isolate(made, owner, []ACE{
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
	made := filepath.Join(handed, "made.txt")
	if err := os.WriteFile(made, []byte("the operator wrote this"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Isolate(handed, unusedAccount, []ACE{
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
	if err := Isolate(t.TempDir(), "nobody in particular", []ACE{
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

	if err := Isolate(handed, owner, writable, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(made, []byte(written), 0o644); err != nil {
		t.Fatalf("a writable grant stopped working: %v", err)
	}

	if err := Isolate(handed, owner, readable, InheritObjects|InheritContainers, nil); err != nil {
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
	if err := Isolate(handed, owner, writable, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(made, []byte("writable again"), 0o644); err != nil {
		t.Fatalf("a grant widened back did not make its own files writable again: %v", err)
	}
}
