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
