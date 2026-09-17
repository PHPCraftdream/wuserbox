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
	const original = "the sandbox wrote this"
	if !box.tries(t, `cmd.exe /c echo `+original+`> "own\made.txt"`, work) {
		t.Fatal("the sandbox could not write its own file inside a writable grant, so everything below proves nothing")
	}
	if !exists(made) {
		t.Fatal("the file the sandbox wrote is not there, so everything below proves nothing")
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

	// The list as the narrowing left it. Everything below is refused, so this
	// is the list the refusals must leave standing.
	before, err := exec.Command("icacls", made).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v\n%s", made, err, before)
	}

	overwrite := `cmd.exe /c echo tampered> "own\made.txt"`
	remove := `cmd.exe /c del /q "own\made.txt"`
	rewrite := `icacls "` + made + `" /grant *` + account.String() + `:(F)`
	resettleMade := `icacls "` + made + `" /setowner *` + account.String()

	// Two rounds, each a fresh logon: under the narrowing, and after the
	// grant is gone entirely. The second is the half the first hides -- the
	// narrowing's own refusals are still on the tree then -- and the half
	// that was broken: with the grant gone there is no refusal left to hide
	// behind, and ownership's WRITE_DAC was the way back in.
	for _, phase := range []struct{ how string }{
		{"the read-only grant"},
		{"the revoked grant"},
	} {
		if phase.how == "the revoked grant" {
			// The record's part in a revoke is bookkeeping; what is measured
			// is the file system, so the revoke goes through the same two
			// calls State.Remove makes.
			if err := grant.Revoke(box.sid, work); err != nil {
				t.Fatal(err)
			}
			if err := grant.Prune(box.sid, work, nil); err != nil {
				t.Fatal(err)
			}
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
		if got, err := os.ReadFile(made); err != nil || string(got) != original {
			t.Fatalf("the content of %s changed under %s: %q (%v)", made, phase.how, got, err)
		}

		// del is run for its effect and never for its answer, the way every
		// other deletion here is asked about: measured, `del /q` on a file it
		// cannot delete prints "Access is denied." and exits 0 anyway.
		box.tries(t, remove, work)
		if !exists(made) {
			t.Fatalf("%s was deleted from inside the sandbox under %s", made, phase.how)
		}
	}

	// And the refusals undid nothing: the list is the one the narrowing left.
	after, err := exec.Command("icacls", made).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v\n%s", made, err, after)
	}
	if strings.TrimSpace(string(before)) != strings.TrimSpace(string(after)) {
		t.Fatalf("the permission list of %s changed although every attempt was refused:\nbefore:\n%s\nafter:\n%s",
			made, before, after)
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
