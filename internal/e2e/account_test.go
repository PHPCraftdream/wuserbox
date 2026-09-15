// The boundary measured against the mechanism a real run uses: two local
// accounts, each in its own group, started with CreateProcessWithLogonW.
//
// Every other test in this package runs under the restricted token with a
// synthetic SID, which needs no administrator rights and is why they can run
// anywhere. That is also their limit: the token carries a fixed list of
// restricting identities, so an entry naming something outside it reaches
// nobody inside, and a test cannot tell an entry that was taken away from one
// that was never reachable. An account carries what an account carries. This
// file is the only place that difference is visible.
//
// It needs administrator rights and skips without them, the same as
// TestLifecycle, so it runs on CI and not on most desks. Everything it makes
// -- two groups, two accounts, two profiles -- it removes.
//
// This puts internal/e2e at eight entries where the layout rules ask for
// about seven, and puts this file a little over the five hundred lines they
// ask for as well. Named rather than quietly picked, as CONTRIBUTING asks.
// Folding it into a file about the old mechanism was the first alternative,
// and the whole point of it is that it is not that. Splitting it in two is
// the second, and it would make the directory worse to pay for making the
// file better -- these tests share one fixture, the real sandbox in
// newRealBox, and every one of them is about what that fixture can and
// cannot reach.

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	acct "github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/exec"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// realBox is a sandbox built the way --init builds one: a local group that
// carries its permissions, a local account that is its only member and runs
// as it, and a thin profile of its own so logging it on builds nothing in
// C:\Users.
type realBox struct {
	group    string
	account  string
	password string
	sid      string
}

// Two sandboxes need two accounts, and an account's name is derived from the
// last eight characters of its group's -- the readable part in front is
// dropped, because NetUserAdd caps a name at twenty characters. So two groups
// have to differ there and not merely somewhere: named wub-e2e-one-0000dead
// and wub-e2e-two-0000dead, both accounts came out wub-0000dead and the
// second came back as one that already exists. Measured, elevated.
const (
	firstSandbox  = "0000dea1"
	secondSandbox = "0000dea2"
)

func requireAdministrator(t *testing.T) {
	t.Helper()
	if !token.IsAdmin() {
		t.Skip("building a real sandbox account needs administrator rights")
	}
}

// newRealBox makes one and takes it away again when the test ends.
func newRealBox(t *testing.T, label, dir string) *realBox {
	t.Helper()
	groupName := group.Prefix + "e2e-" + label
	if err := group.Add(groupName, dir); err != nil {
		t.Fatalf("creating the group for %s: %v", label, err)
	}
	t.Cleanup(func() { _ = group.Delete(groupName) })

	name := acct.NameFor(groupName)
	password, err := acct.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := acct.Add(name, dir, password); err != nil {
		t.Fatalf("creating the account for %s: %v", label, err)
	}
	t.Cleanup(func() { _ = acct.Delete(name) })

	value, err := sid.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	builtinUsers, err := acct.BuiltinUsersName()
	if err != nil {
		t.Fatal(err)
	}
	if err := acct.EnsureMembership(name, groupName, builtinUsers); err != nil {
		t.Fatal(err)
	}
	// Configured exactly as --init configures one. Whether a logon still
	// succeeds against an account hidden from the sign-in screen and denied
	// remote logon was the design's oldest unmeasured question; running
	// anything at all below is the answer.
	if err := acct.HideFromSignIn(name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = acct.UnhideFromSignIn(name) })
	if err := acct.DenyRemoteLogon(name); err != nil {
		t.Fatal(err)
	}

	// A profile of our own, so LOGON_WITH_PROFILE has one to load and
	// Windows builds nothing in C:\Users that would outlive the test.
	//
	// Deliberately not under t.TempDir(). The profile service keeps the hive
	// loaded for a while after the process that used it has gone, and
	// DeleteProfileW will not unload one it never made, so the directory
	// cannot reliably be deleted the moment the test ends -- measured, on
	// UsrClass.dat. t.TempDir() fails the test over that. This is removed if
	// it can be and left if it cannot, because a couple of megabytes of
	// temporary files is not a reason to report that the boundary does not
	// hold.
	profile, err := os.MkdirTemp("", "wuserbox-e2e-profile-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(profile) })
	if err := acct.MakeProfile(profile, value); err != nil {
		t.Fatalf("making the profile for %s: %v", label, err)
	}
	if err := acct.RegisterProfile(value, profile); err != nil {
		t.Fatalf("registering the profile for %s: %v", label, err)
	}
	t.Cleanup(func() {
		_ = acct.DeleteProfile(value.String())
		_ = acct.RemoveProfileServiceReference(value)
	})

	groupSID, err := sid.Lookup(groupName)
	if err != nil {
		t.Fatal(err)
	}
	return &realBox{group: groupName, account: name, password: password, sid: groupSID.String()}
}

// hand gives a directory to this sandbox, the way --grant does.
func (b *realBox) hand(t *testing.T, dir string, kind grant.Kind) {
	t.Helper()
	s := &state.State{Group: b.group, SID: b.sid, Dir: dir}
	if err := s.Add(dir, kind); err != nil {
		t.Fatalf("handing %s to %s: %v", dir, b.group, err)
	}
}

// tries runs a command line as this sandbox's own account and says whether
// it succeeded.
func (b *realBox) tries(t *testing.T, commandLine, dir string) bool {
	return b.ends(t, commandLine, dir) == 0
}

// ends is the same run, answered with the code the program ended on.
func (b *realBox) ends(t *testing.T, commandLine, dir string) int {
	t.Helper()
	code, err := proc.RunAsAccount(b.account, b.password, commandLine, dir, os.Environ())
	if err != nil {
		t.Fatalf("starting %q as %s: %v", commandLine, b.account, err)
	}
	return code
}

// openToEveryone makes a directory readable the way Program Files is, so a
// refusal below comes from what this test arranged and not from wherever the
// machine keeps its temporary files.
func openToEveryone(t *testing.T, dir string) {
	t.Helper()
	if err := acl.Set(dir, sid.Everyone, []acl.ACE{
		{Access: acl.AccessReadExecute, Inheritance: acl.InheritObjects | acl.InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
}

func writeInto(dir string) string {
	return `cmd.exe /c echo written> "` + filepath.Join(dir, "written.txt") + `"`
}

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

// TestAShellStartsInsideARealAccount is the whole reason a sandbox stopped
// being a restricted token. Under one, bash died before main with "couldn't
// create signal pipe, Win32 error 5", and no change to the restricting list
// could fix it.
func TestAShellStartsInsideARealAccount(t *testing.T) {
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
	box := newRealBox(t, firstSandbox, root)
	box.hand(t, root, grant.RW)

	if !box.tries(t, `"`+bash+`" --version`, root) {
		t.Error("bash did not start inside a sandbox, which is the failure the account exists to remove")
	}
}

// The stub is the product's own, reached the way a run reaches it: a binary
// started as the sandbox account, which restricts its own token and runs the
// real command under that. Only the binary differs -- this test binary stands
// in for wuserbox.exe, because building the real one for every test run would
// buy nothing the copy below does not already prove.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == exec.StubFlag {
		if err := exec.Stub(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "stub:", err)
			os.Exit(90)
		}
		// Reached only where the stub was asked for a token and nothing more;
		// with a program to run it ends on that program's own exit code.
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// throughTheStub builds the command line that reaches the program by way of
// the stub, so what runs is confined twice: once by being the account, once
// by the account's own restricted token.
func (b *realBox) throughTheStub(t *testing.T, stubExe, commandLine string) string {
	t.Helper()
	line, err := exec.StubLine(stubExe, b.sid, commandLine)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// stubBinary puts a copy of this test binary somewhere the sandbox account
// can actually start it, and answers where.
//
// Not a detail: the account is not the person running the tests, and the
// test binary lives under that person's own temporary directory, which the
// account cannot read. CreateProcessWithLogonW then refuses with "access is
// denied" before any of this has had a chance to be wrong -- measured on CI,
// the first time these ran. The same holds for the product: whatever plays
// the stub has to be readable and executable by the account, and a wuserbox
// installed into a profile would not be.
func stubBinary(t *testing.T, root string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	from, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	// Inside root, which openToEveryone has already made readable and
	// executable the way Program Files is.
	stub := filepath.Join(root, "stub.exe")
	if err := os.WriteFile(stub, from, 0o755); err != nil {
		t.Fatal(err)
	}
	return stub
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

// TestTheExitCodeComesBackFromInsideTheSandbox is the property everything
// built on wuserbox depends on and nothing else here measures: `wuserbox go
// test` has to fail when the tests fail.
//
// It is measured on the real chain rather than on the shape of it, because
// the chain is where it could go wrong: the code is read and handed on twice,
// once by the stub inside the account and once by the run out here, across a
// logon boundary in between. 7, because 1 is what half the things that go
// wrong on the way report by themselves.
func TestTheExitCodeComesBackFromInsideTheSandbox(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	stub := stubBinary(t, root)
	box := newRealBox(t, firstSandbox, root)
	box.hand(t, root, grant.RW)

	if code := box.ends(t, box.throughTheStub(t, stub, `cmd.exe /c exit 7`), root); code != 7 {
		t.Errorf("the run ended with %d, and the program inside ended with 7", code)
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
	owned := filepath.Join(root, "owned")
	if err := os.Mkdir(owned, 0o755); err != nil {
		t.Fatal(err)
	}
	box := newRealBox(t, firstSandbox, root)
	box.hand(t, root, grant.RW)

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
	if !box.tries(t, writeInto(owned), root) {
		t.Fatal("a directory granted to the account was not writable by it, so nothing below means anything")
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
