// The seat the shield tests measure from: a real local sandbox account of
// their own, made the way --init makes one, started with RunAsAccount the
// way a run starts its stub, and removed when the test ends.
//
// Why this seat and not the test process's own identity: that stand-in was
// valid only for as long as the process running the tests was never an
// administrator. The CI runner runs as the built-in Administrator (RID -500),
// and a deny-first list shutting a process to an admin member's own SID
// intercepts every question that seat asks before the deliberate
// Administrators allow answers it, so a measurement taken from the runner's
// own identity says nothing about what a real run's seat sees. A run's real
// seat is a dedicated account (internal/account) and never an administrator,
// and that is what this fixture builds and sits the tests in.
//
// Everything here needs administrator rights and skips without them. CI runs
// the tests that use it by name in the Delete boundary step, where a skip is
// a failure.

package proc

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	acct "github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

func requireAdministrator(t *testing.T) {
	t.Helper()
	if !token.IsAdmin() {
		t.Skip("shutting a process to a real account needs administrator rights: the account itself has to be created")
	}
}

// shutAccount is one fixture account: the name and password the logon is
// made with, and the identifier everything that hands the account anything
// is written against.
type shutAccount struct {
	name     string
	password string
	sid      sid.Value
}

// builtinAdministratorsName resolves BUILTIN\Administrators the way
// account.BuiltinUsersName resolves Users: the bare alias name
// NetLocalGroupAddMembers needs is only spelled "Administrators" on an
// English-language install, so the well-known SID is carried and resolved
// rather than the name written down.
func builtinAdministratorsName() (string, error) {
	adminsPointer, err := sid.Parse(sid.Administrators)
	if err != nil {
		return "", err
	}
	return sid.Name(adminsPointer)
}

// aShutAccount makes one account and takes it away again when the test ends.
// administrator says whether it is made a member of the Administrators alias
// before its first logon, which is what the second shut test pins.
func aShutAccount(t *testing.T, label string, administrator bool) *shutAccount {
	t.Helper()
	requireAdministrator(t)
	name := acct.Prefix + label
	// A previous run that died between creation and cleanup leaves the
	// account behind, and a fixture that cannot resume over its own earlier
	// success would fail forever after one crash -- the same reason
	// account.AddMember treats an existing membership as a no-op.
	_ = acct.Delete(name)
	password, err := acct.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := acct.Add(name, "wuserbox shield fixture", password); err != nil {
		t.Fatalf("creating the account %s: %v", name, err)
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
	if err := acct.EnsureMembership(name, builtinUsers); err != nil {
		t.Fatal(err)
	}
	if administrator {
		// Membership is fixed at logon, so this has to happen before the
		// fixture's account ever logs on -- which is exactly why the account
		// is built before anything runs as it.
		admins, err := builtinAdministratorsName()
		if err != nil {
			t.Fatal(err)
		}
		if err := acct.EnsureMembership(name, admins); err != nil {
			t.Fatal(err)
		}
	}

	// Configured exactly as --init configures one. Whether a logon still
	// succeeds against an account hidden from the sign-in screen and denied
	// remote logon is answered by anything running at all below.
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
	profile, err := os.MkdirTemp("", "wuserbox-shield-profile-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(profile) })
	if err := acct.MakeProfile(profile, value); err != nil {
		t.Fatalf("making the profile for %s: %v", name, err)
	}
	if err := acct.RegisterProfile(value, profile); err != nil {
		t.Fatalf("registering the profile for %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = acct.DeleteProfile(value.String())
		_ = acct.RemoveProfileServiceReference(value)
	})

	return &shutAccount{name: name, password: password, sid: value}
}

// openToEveryone makes a directory readable the way Program Files is, so a
// refusal below comes from what the test arranged and not from wherever the
// machine keeps its temporary files: the account is not the person running
// the tests and must be able to reach what it is asked to start.
func openToEveryone(t *testing.T, dir string) {
	t.Helper()
	if err := acl.Set(dir, sid.Everyone, []acl.ACE{
		{Access: acl.AccessReadExecute, Inheritance: acl.InheritObjects | acl.InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
}

// fixtureTree builds everything the fixture run reaches: the root the account
// can read and execute from, the work directory its children write into, and
// a copy of this test binary the account can actually start.
//
// The copy is not a detail: the account is not the person running the tests,
// and the test binary lives under that person's own temporary directory,
// which the account cannot read. CreateProcessWithLogonW then refuses with
// "access is denied" before anything else has had a chance to be wrong --
// measured on CI.
func fixtureTree(t *testing.T, a *shutAccount) (root, work, exe string) {
	t.Helper()
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	work = filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	// The fixture children write their diagnosis and the prober children
	// their answers here, and a plain Everyone read of the root does not let
	// them write.
	if err := acl.Set(work, a.sid.String(), []acl.ACE{
		{Access: acl.AccessModify, Inheritance: acl.InheritObjects | acl.InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
	from, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	// Inside root, which openToEveryone has already made readable and
	// executable the way Program Files is.
	exe = filepath.Join(root, "fixture.exe")
	if err := os.WriteFile(exe, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	return root, work, exe
}

// runFixture starts this binary as the account the way a run starts its stub,
// waits for it, and reads its exit code as the verdict. A nonzero end is
// backed by the diagnosis file the child wrote, read best effort: the exit
// code is the verdict, the file only the words that explain it.
func (a *shutAccount) runFixture(t *testing.T, exe, work, flag string) {
	t.Helper()
	line := syscall.EscapeArg(exe) + " " + flag + " " + syscall.EscapeArg(work)
	code, err := RunAsAccount(a.name, a.password, line, work, os.Environ())
	if err != nil {
		t.Fatalf("starting the fixture as %s: %v", a.name, err)
	}
	if code != 0 {
		what, readErr := os.ReadFile(filepath.Join(work, "diagnosis.txt"))
		if readErr != nil {
			what = []byte(fmt.Sprintf("unreadable: %v", readErr))
		}
		t.Fatalf("the fixture run as %s ended with exit code %d; what it wrote: %s", a.name, code, what)
	}
}

// fixtureFailed reports a fixture child's failure the only channel its parent
// can be sure of, the exit code, with the words that explain it left in the
// diagnosis file -- the same split the prowler's exit code and the e2e conhost
// prowl's findings use.
func fixtureFailed(dir string, err error) int {
	_ = os.WriteFile(filepath.Join(dir, "diagnosis.txt"), []byte(err.Error()), 0o600)
	return middleBroke | 1
}
