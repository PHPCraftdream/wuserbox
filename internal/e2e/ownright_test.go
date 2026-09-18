// The objects a sandbox creates while a grant is writable are owned by the
// sandbox's account, and ownership carries WRITE_DAC and READ_CONTROL with it,
// counted after every refusal the permission list makes -- so the refusal a
// read-only grant writes did not hold against anything the sandbox had made,
// and icacls gave it its access back. What follows the sandbox's own objects
// through a narrowing and a revoke on a real account: the refusals hold, the
// reading stays, the content and the list are the same afterwards, and the
// operator can still delete what the sandbox left behind.
//
// Needs a real account: the hole is in what ownership adds to the access
// check, and a synthetic identifier owns nothing. Skips without
// administrator rights, like the tests beside it. The token's second check is
// TestAReadOnlyHandoverHoldsOnTheSecondEntry's subject; this test holds the
// logon plain on purpose, because what it measures is the list, and the
// plain account is the half where only the list can refuse.
package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

func TestWhatTheSandboxOwnsStaysLockedAfterTheGrantIsGone(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	work := filepath.Join(root, "work")   // handed over writable, then read-only, then taken back
	probe := filepath.Join(root, "probe") // the account's to change, so the probes are shown working
	for _, dir := range []string{work, probe} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	box := newRealBox(t, firstSandbox, work)
	account, err := sid.Lookup(box.account)
	if err != nil {
		t.Fatal(err)
	}
	if err := acl.ProtectFull(probe, account.String()); err != nil {
		t.Fatal(err)
	}
	box.hand(t, work, grant.RW)

	// What the sandbox leaves behind when it works: a directory of its own
	// and a file in it, both owned by the account.
	if !box.tries(t, `cmd.exe /c mkdir own`, work) {
		t.Fatal("the sandbox could not make its own directory inside a writable grant, so everything below proves nothing")
	}
	made := filepath.Join(work, "own", "made.txt")
	if !box.tries(t, `cmd.exe /c echo the sandbox wrote this> "own\made.txt"`, work) {
		t.Fatal("the sandbox could not write its own file inside a writable grant, so everything below proves nothing")
	}
	// The actual bytes, not the text handed to echo: cmd.exe appends its own
	// line ending, and comparing against the literal string later would fail
	// on a boundary that held perfectly.
	original, err := os.ReadFile(made)
	if err != nil {
		t.Fatalf("the file the sandbox wrote is not there, so everything below proves nothing: %v", err)
	}
	accountACE := `icacls "` + made + `" /grant *` + account.String() + `:(F)`
	if !box.tries(t, accountACE, work) {
		t.Fatal("the sandbox account could not grant itself an explicit account ACE while the grant was writable, so the regression would prove nothing")
	}

	// Both probes shown working where the account holds every right, the way
	// the tests beside this one hold theirs: a refusal below must not be a
	// syntax error or a right the account never had.
	grantIt := `icacls "` + probe + `" /grant *` + account.String() + `:(F)`
	resettle := `icacls "` + probe + `" /setowner *` + account.String()
	for _, attempt := range []string{grantIt, resettle} {
		if !box.tries(t, attempt, work) {
			t.Fatalf("%q did not work where the account holds every right, so a refusal of it below proves nothing", attempt)
		}
	}

	// The narrowing. The read-only grant's entries refuse the group every
	// changing right; what they cannot refuse is what ownership adds, which
	// is the subject from here on.
	box.hand(t, work, grant.RO)

	overwrite := `cmd.exe /c echo tampered> "own\made.txt"`
	remove := `cmd.exe /c del /q "own\made.txt"`
	rewrite := `icacls "` + made + `" /grant *` + account.String() + `:(F)`
	resettleMade := `icacls "` + made + `" /setowner *` + account.String()

	// Two rounds, each a fresh logon: under the narrowing, and after the
	// grant is gone entirely. The second is the half the first hides -- the
	// narrowing's own refusals are still on the tree then -- and the half
	// that was broken: with the grant gone there is no refusal left to hide
	// behind, and ownership's WRITE_DAC was the way back in.
	//
	// Revoking is a legitimate change the record's own path makes to this
	// same list, so the baseline the refused attempts must leave standing is
	// taken fresh inside each phase, after that phase's own legitimate
	// change and before anything refused runs against it -- not once before
	// the loop, which the revoke would then be measured against too.
	for _, phase := range []struct{ how string }{
		{"the read-only grant"},
		{"the revoked grant"},
	} {
		if phase.how == "the revoked grant" {
			// The record's part in a revoke is bookkeeping; what is measured
			// is the file system, so the revoke goes through the same two
			// calls State.Remove makes.
			if err := grant.Revoke(box.sid, work, nil); err != nil {
				t.Fatal(err)
			}
			if err := grant.Prune(box.sid, work, nil); err != nil {
				t.Fatal(err)
			}
		}

		// The list this phase's own legitimate change left. Everything below
		// is refused, so this is the list the refusals must leave standing.
		before, err := exec.Command("icacls", made).CombinedOutput()
		if err != nil {
			t.Fatalf("icacls %s: %v\n%s", made, err, before)
		}

		// Reading is the positive the refusals stand on: without it they say
		// only that the sandbox cannot see the file at all. The cap leaves
		// the owner read-and-execute, and the tree hands Everyone its reading.
		if !box.tries(t, `cmd.exe /c type "own\made.txt"`, work) {
			t.Fatalf("reading what the sandbox wrote no longer works under %s", phase.how)
		}

		if box.tries(t, rewrite, work) {
			t.Fatalf("the permission list of %s was rewritten from inside under %s", made, phase.how)
		}
		if box.tries(t, resettleMade, work) {
			t.Fatalf("ownership of %s was taken from inside under %s", made, phase.how)
		}
		if box.tries(t, overwrite, work) {
			t.Fatalf("a file the sandbox owns was rewritten under %s", phase.how)
		}
		if got, err := os.ReadFile(made); err != nil || !bytes.Equal(got, original) {
			t.Fatalf("the content of %s changed under %s: %q (%v)", made, phase.how, got, err)
		}

		// del is run for its effect and never for its answer, the way every
		// other deletion here is asked about: measured, `del /q` on a file it
		// cannot delete prints "Access is denied." and exits 0 anyway.
		box.tries(t, remove, work)
		if !exists(made) {
			t.Fatalf("%s was deleted from inside the sandbox under %s", made, phase.how)
		}

		// And the refusals undid nothing within this phase: the list is the
		// one this phase's own legitimate change left.
		after, err := exec.Command("icacls", made).CombinedOutput()
		if err != nil {
			t.Fatalf("icacls %s: %v\n%s", made, err, after)
		}
		if strings.TrimSpace(string(before)) != strings.TrimSpace(string(after)) {
			t.Fatalf("the permission list of %s changed under %s although every attempt was refused:\nbefore:\n%s\nafter:\n%s",
				made, phase.how, before, after)
		}
	}

	// The operator's re-permission path -- what --ro and --revoke run
	// through: the cap binds the owner, and the operator is not the owner.
	// The entry the tree handed down carries WRITE_DAC for the account that
	// granted the tree, and this is what makes a capped object something the
	// operator can still change the terms of.
	caller, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", made, "/grant", "*"+caller+":(F)").CombinedOutput(); err != nil {
		t.Fatalf("the operator could not re-permission what the sandbox owns, which would make the cap a one-way door for --ro and --revoke:\n%s", out)
	}

	// The recovery the operator keeps: the account's own entry, inherited
	// from the tree it handed over, carries DELETE here -- the same entry
	// that lets the temporary directory be removed once the account below
	// has been taken away. Were this to fail, the cap would be a one-way
	// door with the operator on the wrong side of it.
	if err := os.Remove(made); err != nil {
		t.Fatalf("the operator could not delete what the sandbox left behind: %v", err)
	}
}

// TestRevokeCapsAnInheritedObjectWithAnExplicitBroadGrant measures the
// inherited branch of TakeBack with a fresh restricted process. A file made
// inside the grant keeps the grant as inherited access; while that grant is
// writable the sandbox can add an explicit Everyone grant beside it. Revoke
// must narrow both, while a sibling without the extra grant is the control.
func TestRevokeCapsAnInheritedObjectWithAnExplicitBroadGrant(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}

	box := newRealBox(t, firstSandbox, work)
	box.hand(t, work, grant.RW)
	if !box.tries(t, `cmd.exe /c mkdir own`, work) {
		t.Fatal("the sandbox could not make its own directory inside a writable grant")
	}
	broad := filepath.Join(work, "own", "broad.txt")
	control := filepath.Join(work, "own", "control.txt")
	for _, path := range []string{broad, control} {
		name := filepath.Base(path)
		if !box.tries(t, `cmd.exe /c echo original> "own\`+name+`"`, work) {
			t.Fatalf("the sandbox could not create %s", name)
		}
	}

	// The extra grant is written by the sandbox itself, alongside the
	// inherited grant. The control has the inherited grant only.
	expand := `icacls "` + broad + `" /grant *` + sid.Everyone + `:(F)`
	if !box.tries(t, expand, work) {
		t.Fatal("the sandbox could not add the explicit Everyone grant")
	}
	if !acl.EveryoneWritable(broad) {
		t.Fatal("the explicit Everyone grant was not writable before revoke")
	}
	if acl.EveryoneWritable(control) {
		t.Fatal("the control unexpectedly had a broad explicit grant")
	}
	aclText, err := exec.Command("icacls", broad).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v\n%s", broad, err, aclText)
	}
	if !strings.Contains(string(aclText), "(I)") {
		t.Fatalf("the broad probe has no inherited ACE; the inherited revoke branch was not exercised:\n%s", aclText)
	}

	// Both files are writable before revoke. Each later attempt runs through a
	// new logon and therefore cannot succeed through an old open handle.
	for _, name := range []string{"broad.txt", "control.txt"} {
		if !box.tries(t, `cmd.exe /c echo before> "own\`+name+`"`, work) {
			t.Fatalf("the sandbox could not rewrite %s before revoke", name)
		}
	}
	if err := grant.Revoke(box.sid, work, nil); err != nil {
		t.Fatal(err)
	}
	if err := grant.Prune(box.sid, work, nil); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{broad, control} {
		name := filepath.Base(path)
		if box.tries(t, `cmd.exe /c echo after> "own\`+name+`"`, work) {
			t.Fatalf("a fresh restricted process rewrote %s after revoke", name)
		}
		if box.tries(t, `icacls "`+path+`" /grant *`+box.sid+`:(F)`, work) {
			t.Fatalf("a fresh restricted process changed the DACL of %s after revoke", name)
		}
		box.tries(t, `cmd.exe /c del /q "own\`+name+`"`, work)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("revoke cleanup removed %s from the control tree: %v", name, err)
		}
	}

	caller, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{broad, control} {
		if out, err := exec.Command("icacls", path, "/grant", "*"+caller+":(F)").CombinedOutput(); err != nil {
			t.Fatalf("the operator could not recover %s after revoke: %v\n%s", path, err, out)
		}
		if err := os.Remove(path); err != nil {
			t.Fatalf("the operator could not remove %s after recovery: %v", path, err)
		}
	}
}

// TestADirectRevokeCapsAFileTheSandboxOwnsWithNoNarrowingFirst is the branch
// the review found missing: --revoke on its own, with no --ro before it. A
// narrowing writes the cap through the sweep on its way in; a direct revoke
// is the only place TakeBack does that work alone, and this is the one
// sequence that never exercises the sweep at all.
func TestADirectRevokeCapsAFileTheSandboxOwnsWithNoNarrowingFirst(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}

	box := newRealBox(t, firstSandbox, work)
	box.hand(t, work, grant.RW)

	if !box.tries(t, `cmd.exe /c mkdir own`, work) {
		t.Fatal("the sandbox could not make its own directory inside a writable grant, so everything below proves nothing")
	}
	made := filepath.Join(work, "own", "made.txt")
	if !box.tries(t, `cmd.exe /c echo the sandbox wrote this> "own\made.txt"`, work) {
		t.Fatal("the sandbox could not write its own file inside a writable grant, so everything below proves nothing")
	}
	original, err := os.ReadFile(made)
	if err != nil {
		t.Fatalf("the file the sandbox wrote is not there, so everything below proves nothing: %v", err)
	}
	accountSID, err := sid.Lookup(box.account)
	if err != nil {
		t.Fatal(err)
	}
	accountACE := `icacls "` + made + `" /grant *` + accountSID.String() + `:(F)`
	if !box.tries(t, accountACE, work) {
		t.Fatal("the sandbox account could not grant itself an explicit account ACE while the grant was writable, so the direct-revoke regression would prove nothing")
	}

	rewrite := `icacls "` + made + `" /grant *` + box.sid + `:(F)`
	if !box.tries(t, rewrite, work) {
		t.Fatal("the account could not rewrite its own file's list while the grant was still writable, so a refusal of it below proves nothing")
	}

	// Straight to revoke: no --ro in between, so the sweep that writes the
	// cap on the way in never runs. If the cap only ever arrived through
	// that sweep, this file would keep its owner's implicit WRITE_DAC.
	if err := grant.Revoke(box.sid, work, nil); err != nil {
		t.Fatal(err)
	}
	if err := grant.Prune(box.sid, work, nil); err != nil {
		t.Fatal(err)
	}

	if box.tries(t, rewrite, work) {
		t.Fatal("the permission list of a sandbox-owned file was rewritten from inside after a direct revoke with no narrowing first")
	}
	if box.tries(t, `cmd.exe /c echo tampered> "own\made.txt"`, work) {
		t.Fatal("a file the sandbox owns was rewritten after a direct revoke with no narrowing first")
	}
	if got, err := os.ReadFile(made); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("the content of %s changed: %q (%v)", made, got, err)
	}

	caller, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", made, "/grant", "*"+caller+":(F)").CombinedOutput(); err != nil {
		t.Fatalf("the operator could not re-permission what a direct revoke left behind:\n%s", out)
	}
	if err := os.Remove(made); err != nil {
		t.Fatalf("the operator could not delete what a direct revoke left behind: %v", err)
	}
}

// TestARevokeReachesAnObjectTheSandboxGaveItselfADACL is the other branch the
// review found missing: a sandbox holding every right on its own file can
// write that file a permission list of its own -- protected, naming itself,
// nothing inherited -- and StripOwn's old job passed such an object whole,
// leaving the self-granted list standing after a revoke that was supposed to
// take everything back.
func TestARevokeReachesAnObjectTheSandboxGaveItselfADACL(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}

	box := newRealBox(t, firstSandbox, work)
	box.hand(t, work, grant.RW)

	if !box.tries(t, `cmd.exe /c mkdir own`, work) {
		t.Fatal("the sandbox could not make its own directory inside a writable grant, so everything below proves nothing")
	}
	self := filepath.Join(work, "own", "self.txt")
	if !box.tries(t, `cmd.exe /c echo the sandbox wrote this> "own\self.txt"`, work) {
		t.Fatal("the sandbox could not write its own file inside a writable grant, so everything below proves nothing")
	}
	original, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("the file the sandbox wrote is not there, so everything below proves nothing: %v", err)
	}

	// A list of the sandbox's own making: protected, full control, nothing
	// inherited and no mark -- the shape a sandbox can write while it still
	// holds every right, and the shape the review's P0-2 asked to be
	// reached anyway.
	sealIt := `icacls "` + self + `" /inheritance:r /grant *` + box.sid + `:(F)`
	if !box.tries(t, sealIt, work) {
		t.Fatal("the sandbox could not seal its own file with a list of its own while the grant was still writable, so everything below proves nothing")
	}

	box.hand(t, work, grant.RO)
	if err := grant.Revoke(box.sid, work, nil); err != nil {
		t.Fatal(err)
	}
	if err := grant.Prune(box.sid, work, nil); err != nil {
		t.Fatal(err)
	}

	rewrite := `icacls "` + self + `" /grant *` + box.sid + `:(F)`
	if box.tries(t, rewrite, work) {
		t.Fatal("the permission list the sandbox gave itself survived a revoke that was supposed to take it back")
	}
	if box.tries(t, `cmd.exe /c echo tampered> "own\self.txt"`, work) {
		t.Fatal("a file the sandbox sealed with its own full-control list was rewritten after a revoke")
	}
	if got, err := os.ReadFile(self); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("the content of %s changed: %q (%v)", self, got, err)
	}

	caller, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", self, "/grant", "*"+caller+":(F)").CombinedOutput(); err != nil {
		t.Fatalf("the operator could not re-permission a file the sandbox had sealed and a revoke then took back:\n%s", out)
	}
	if err := os.Remove(self); err != nil {
		t.Fatalf("the operator could not delete what was left behind: %v", err)
	}
}
