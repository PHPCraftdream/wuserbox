// What an account's own token reaches and what it does not, measured on the
// mechanism a real run uses rather than on the older restricted token with a
// synthetic SID. The fixture these borrow -- newRealBox, and the stub binary
// beside it -- is in account_test.go, and the reason it has to be a real
// account is argued there.

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// TestTwoRealAccountsCannotReachEachOther is the boundary measured on the
// mechanism a run actually uses.
func TestTwoRealAccountsCannotReachEachOther(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	mine := filepath.Join(root, "mine")
	theirs := filepath.Join(root, "theirs")
	for _, dir := range []string{mine, theirs} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	first := newRealBox(t, firstSandbox, mine)
	second := newRealBox(t, secondSandbox, theirs)
	first.hand(t, mine, grant.RW)
	second.hand(t, theirs, grant.RW)

	if !first.tries(t, writeInto(mine), mine) {
		t.Fatal("a sandbox could not write to the directory it was given, so nothing below means anything")
	}
	if second.tries(t, writeInto(mine), theirs) {
		t.Error("one sandbox wrote into the directory another was given")
	}
	victim := filepath.Join(mine, "written.txt")
	if second.tries(t, `cmd.exe /c del /q "`+victim+`"`, theirs) && !exists(victim) {
		t.Error("one sandbox deleted a file in the directory another was given")
	}
}

// TestAGrantTakesAuthenticatedUsersAwayFromEveryOtherAccount is the same P0
// the list-level guard covers, measured where it actually bites.
//
// Authenticated Users is carried by every account that logged on, so an entry
// naming it on a granted directory is an entry every other sandbox holds. The
// restricted token never carried it, which is why no test saw this for as
// long as the tests were the only thing exercising the boundary.
//
// The pair is what makes it mean something. A directory nobody was granted
// proves the entry really does reach an account -- without that, the refusal
// below could come from Authenticated Users granting nothing here at all, and
// the test would pass on a machine where it proves nothing.
func TestAGrantTakesAuthenticatedUsersAwayFromEveryOtherAccount(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	shared := filepath.Join(root, "shared") // open, never handed to anybody
	handed := filepath.Join(root, "handed") // open, then handed to one sandbox
	owned := filepath.Join(root, "owned")   // the other sandbox's own
	for _, dir := range []string{shared, handed, owned} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := acl.Set(dir, sid.Authenticated, []acl.ACE{
			{Access: acl.AccessModify, Inheritance: acl.InheritObjects | acl.InheritContainers},
		}); err != nil {
			t.Fatal(err)
		}
	}

	holder := newRealBox(t, firstSandbox, handed)
	other := newRealBox(t, secondSandbox, owned)
	holder.hand(t, handed, grant.RW)
	other.hand(t, owned, grant.RW)

	if !other.tries(t, writeInto(shared), owned) {
		t.Fatal("Authenticated Users:Modify did not let a sandbox write, " +
			"so this machine cannot tell an entry taken away from one that never reached")
	}
	if other.tries(t, writeInto(handed), owned) {
		t.Error("handing a directory over left Authenticated Users on it, " +
			"so every other sandbox on the machine may change it")
	}
}

// TestAShellStartsUnderTheAccountsOwnRestrictedToken is the one measurement
// the whole design rests on.
//
// A restricted token is what used to make this boundary tight, and it was
// given up because MSYS programs could not start under one: the runtime
// writes its own descriptors naming the account it runs as, and a token
// restricted to identities that could not include the caller was refused by
// its own objects -- it could not even query its own process token. Now the
// account it runs as is the sandbox, so that identity can be a restricting
// one, and the thing that broke costs nothing.
//
// If this fails, the account and the restricted token really are
// alternatives and the narrow path is the only one.
func TestAShellStartsUnderTheAccountsOwnRestrictedToken(t *testing.T) {
	requireAdministrator(t)
	const bash = `C:\Program Files\Git\bin\bash.exe`
	if _, err := os.Stat(bash); err != nil {
		t.Skip("Git for Windows is not installed here, so there is no MSYS program to start")
	}
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	stub := stubBinary(t, root)
	box := newRealBox(t, firstSandbox, root)
	box.hand(t, root, grant.RW)

	if !box.tries(t, box.throughTheStub(t, stub, `"`+bash+`" --version`), root) {
		t.Error("bash did not start under the account's own restricted token")
	}
	// And the sandbox can still write what it was actually given.
	if !box.tries(t, box.throughTheStub(t, stub, writeInto(root)), root) {
		t.Error("the sandbox could not write the directory it was granted")
	}
}

// TestTheRestrictedTokenClosesWhatTheAccountAloneCannot is the pair that
// says what the restriction buys.
//
// C:\Users\Public carries INTERACTIVE:(OI)(CI)(M,DC) on an ordinary Windows,
// and every account that logs on interactively carries INTERACTIVE. So a
// plain account reaches such a directory although nobody granted it
// anything -- measured here as the first half, which is what keeps the
// second half from passing for the wrong reason. Under a token restricted to
// the sandbox's own identities, the same write is refused: INTERACTIVE is
// not one of them, and no list of SIDs had to be kept complete to say so.
func TestTheRestrictedTokenClosesWhatTheAccountAloneCannot(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	shared := filepath.Join(root, "shared") // like C:\Users\Public: never granted
	owned := filepath.Join(root, "owned")
	for _, dir := range []string{shared, owned} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := acl.Set(shared, sid.Interactive, []acl.ACE{
		{Access: acl.AccessModify, Inheritance: acl.InheritObjects | acl.InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}

	stub := stubBinary(t, root)
	box := newRealBox(t, firstSandbox, owned)
	box.hand(t, owned, grant.RW)

	if !box.tries(t, writeInto(shared), owned) {
		t.Fatal("INTERACTIVE did not reach the account here, so the refusal below would prove nothing")
	}
	if box.tries(t, box.throughTheStub(t, stub, writeInto(shared)), owned) {
		t.Error("the restricted token still reached a directory granted only to INTERACTIVE")
	}
}

// TestCheckAnswersWithTheTokenARunGets is the divergence `--check` used to
// carry, measured where it bites.
//
// The answer used to come from a restricted copy of the *caller's* token,
// because building the sandbox's own needed a password. That token carries
// the caller's memberships and never the sandbox account's own identifier, so
// about anything whose permissions name that identifier -- the sandbox's own
// profile above all, which is where its credentials and settings now live --
// it said "refused" about a directory every run writes to.
//
// The pair is what gives it meaning. The first half proves the directory
// really is the sandbox's to write, and the last proves the old answer really
// did get it wrong here, so a passing test cannot be one that measured
// nothing.
func TestCheckAnswersWithTheTokenARunGets(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	// Deliberately not inside what the sandbox was granted. A grant names the
	// group, the group is on the restricting list, and the old answer would
	// then reach this the ordinary way -- measured on CI, where a first
	// version of this test put the directory under the granted root and the
	// two answers agreed for exactly that reason.
	work := filepath.Join(root, "work")   // granted, so there is somewhere to run from
	owned := filepath.Join(root, "owned") // never granted; the account is named on it directly
	for _, dir := range []string{work, owned} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	box := newRealBox(t, firstSandbox, work)
	box.hand(t, work, grant.RW)

	// Named for the account and not the group, the way a thin profile is:
	// account.MakeProfile writes the account's own identifier into it, because
	// at that point the profile belongs to nobody else.
	account, err := sid.Lookup(box.account)
	if err != nil {
		t.Fatal(err)
	}
	if err := acl.Set(owned, account.String(), []acl.ACE{
		{Access: acl.AccessModify, Inheritance: acl.InheritObjects | acl.InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
	if !box.tries(t, writeInto(owned), work) {
		t.Fatal("a directory naming the account was not writable by it, so nothing below means anything")
	}

	written := filepath.Join(owned, "written.txt")
	answer, err := access.Check(access.Sandbox{
		Group: box.sid, Account: box.account, Password: box.password,
	}, written, access.Write)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Allowed {
		t.Errorf("asking said no about a file the sandbox had just written: %s", answer.Reason)
	}
	old, err := access.Check(access.Sandbox{Group: box.sid}, written, access.Write)
	if err != nil {
		t.Fatal(err)
	}
	if old.Allowed {
		t.Fatal("the caller's own restricted token reaches this too, so the answer above proves nothing")
	}
}

// TestAReadOnlyHandoverHoldsOnTheSecondEntry is the read-only grant measured
// on the mechanism a real run uses, which no test here had measured: every
// synthetic check of --ro goes through a made-up SID, and every test that
// builds a real account hands its directory over writable. The synthetic
// token cannot say an entry was taken away rather than never reachable --
// that is what this fixture exists for -- and read-only is nothing but an
// entry taken away.
//
// The handover has to survive two entries, each a fresh logon, so what is
// measured is the permission list the grant left on the directory rather
// than one process's token. The first entry runs as the plain account,
// where only the list can refuse; the second goes through the stub, where
// the restricted token is checked too. Each is the half the other could
// hide.
//
// The icacls probes are held to the pair the other tests here are held to:
// they are shown working first, on a directory the account holds every
// right to, the way MakeProfile builds its own. /setowner does not force a
// change of ownership -- the tool's own help says so -- so what it reports
// is the right the caller holds and nothing else.
func TestAReadOnlyHandoverHoldsOnTheSecondEntry(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	work := filepath.Join(root, "work")     // handed over writable, the way a run's own directory is
	handed := filepath.Join(root, "handed") // handed over read-only, the subject
	probe := filepath.Join(root, "probe")   // the account's to change, so the probes are shown working
	for _, dir := range []string{work, handed, probe} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	const original = "read me"
	kept := filepath.Join(handed, "readable.txt")
	place(t, kept, original)
	box := newRealBox(t, firstSandbox, work)
	box.hand(t, work, grant.RW)
	box.hand(t, handed, grant.RO)

	account, err := sid.Lookup(box.account)
	if err != nil {
		t.Fatal(err)
	}
	if err := acl.ProtectFull(probe, account.String()); err != nil {
		t.Fatal(err)
	}
	stub := stubBinary(t, root)

	// Handing itself the write back, and ownership one step further back:
	// with either right, every refusal above is the sandbox's to undo. The
	// refusal the read-only grant leaves names the group and covers both,
	// which is why these need no entry naming the account at all.
	regrant := `icacls "` + handed + `" /grant *` + account.String() + `:(OI)(CI)F`
	resettle := `icacls "` + handed + `" /setowner *` + account.String()

	for _, attempt := range []string{
		`icacls "` + probe + `" /grant *` + account.String() + `:(OI)(CI)F`,
		`icacls "` + probe + `" /setowner *` + account.String(),
	} {
		if !box.tries(t, box.throughTheStub(t, stub, attempt), work) {
			t.Fatalf("%q did not work where the account holds every right, so a refusal of it below proves nothing", attempt)
		}
	}

	for _, entry := range []struct {
		how     string
		confine func(string) string
	}{
		{"the plain account", func(line string) string { return line }},
		{"the account's own restricted token", func(line string) string { return box.throughTheStub(t, stub, line) }},
	} {
		// Reading is the positive the refusals stand on: without it, they
		// say only that the sandbox cannot see the directory at all.
		if !box.tries(t, entry.confine(`cmd.exe /c type "`+kept+`"`), work) {
			t.Fatalf("reading what was handed over read-only failed through %s, so the refusals below prove nothing", entry.how)
		}
		// And the account still writes what it was handed writable, so the
		// refusals below belong to this grant and not to a broken account.
		if !box.tries(t, entry.confine(writeInto(work)), work) {
			t.Fatalf("the sandbox could not write %s through %s, so the refusals below mean nothing", work, entry.how)
		}

		fresh := filepath.Join(handed, "fresh.txt")
		if box.tries(t, entry.confine(`cmd.exe /c echo fresh> "`+fresh+`"`), work) {
			t.Fatalf("a new file was written into a directory handed over read-only, through %s", entry.how)
		}
		if exists(fresh) {
			t.Fatalf("%s appeared although the write through %s was refused", fresh, entry.how)
		}

		if box.tries(t, entry.confine(`cmd.exe /c echo tampered> "`+kept+`"`), work) {
			t.Fatalf("a file in a directory handed over read-only was rewritten, through %s", entry.how)
		}
		if got, readErr := os.ReadFile(kept); readErr != nil || string(got) != original {
			t.Fatalf("the content of %s changed although the rewrite through %s was refused: %q (%v)", kept, entry.how, got, readErr)
		}

		// del is run for its effect and never for its answer, the way every
		// other deletion in this directory is asked about. Measured on
		// Windows 10: `del /q` on a file it cannot delete prints "Access is
		// denied." and exits 0 anyway, so reading its code would fail this
		// test on a machine where the grant held perfectly. The file still
		// being there is the whole of the answer.
		box.tries(t, entry.confine(`cmd.exe /c del /q "`+kept+`"`), work)
		if !exists(kept) {
			t.Fatalf("%s was deleted from a directory handed over read-only, through %s", kept, entry.how)
		}

		if box.tries(t, entry.confine(regrant), work) {
			t.Fatalf("the permissions of a directory handed over read-only were rewritten from inside, through %s", entry.how)
		}
		if box.tries(t, entry.confine(resettle), work) {
			t.Fatalf("ownership of a directory handed over read-only was taken from inside, through %s", entry.how)
		}
		// The last write is what says the attempts above undid nothing.
		after := filepath.Join(handed, "after.txt")
		if box.tries(t, entry.confine(`cmd.exe /c echo after> "`+after+`"`), work) {
			t.Fatalf("a file was written into the read-only directory after the attempts to take the rights back, through %s", entry.how)
		}
	}
}
