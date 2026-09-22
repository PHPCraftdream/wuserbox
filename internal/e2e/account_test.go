// The fixture the account tests are built on: two local accounts, each in
// its own group, started with CreateProcessWithLogonW, plus the stub binary
// and the plumbing that reads a program's streams back out of one.
//
// Every other test in this package runs under the restricted token with a
// synthetic SID, which needs no administrator rights and is why they can run
// anywhere. That is also their limit: the token carries a fixed list of
// restricting identities, so an entry naming something outside it reaches
// nobody inside, and a test cannot tell an entry that was taken away from one
// that was never reachable. An account carries what an account carries.
//
// Everything built here needs administrator rights and skips without them, so
// it runs on CI and not on most desks. Everything it makes -- two groups, two
// accounts, two profiles -- it removes.
//
// This file used to hold the tests too, and said in this comment that it was
// staying over five hundred lines on purpose: splitting it would have cost
// the directory an entry to save the file some lines, and the tests all share
// this one fixture. The entry count is no longer the thing being defended --
// a directory in Go is a package, so an oversized file can only ever be split
// into siblings beside it, and a rule that forbids that forbids the line
// limit as well. The tests moved out to token_test.go and streams_test.go;
// the fixture they share stayed here.

package e2e

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	acct "github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/exec"
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

// Two sandboxes need two accounts. Account names fit the twenty-character
// NetUserAdd limit while carrying a second hash over the complete group name,
// so groups with the same legacy eight-digit suffix no longer share one.
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

// streams runs the real account-to-stub chain with temporary pipes as its
// standard streams. It keeps the pipes on the caller side and reads them only
// after the process has ended; the command writes a few bytes, so no writer
// can fill while the run is waiting.
func (b *realBox) streams(t *testing.T, stub, dir string) (string, string) {
	t.Helper()
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		inRead.Close()
		inWrite.Close()
		t.Fatal(err)
	}
	errRead, errWrite, err := os.Pipe()
	if err != nil {
		inRead.Close()
		inWrite.Close()
		outRead.Close()
		outWrite.Close()
		t.Fatal(err)
	}

	oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin, os.Stdout, os.Stderr = inRead, outWrite, errWrite
	restore := func() {
		os.Stdin, os.Stdout, os.Stderr = oldIn, oldOut, oldErr
	}
	defer restore()

	if _, err := inWrite.WriteString("from-stdin\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := inWrite.Close(); err != nil {
		t.Fatal(err)
	}
	line := b.throughTheStub(t, stub, `cmd.exe /c "(more & echo stdout & echo stderr 1>&2)"`)
	code, runErr := proc.RunAsAccount(b.account, b.password, line, dir, os.Environ())
	if err := outWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := errWrite.Close(); err != nil {
		t.Fatal(err)
	}
	stdout, readOutErr := io.ReadAll(outRead)
	stderr, readErrErr := io.ReadAll(errRead)
	_ = inRead.Close()
	_ = outRead.Close()
	_ = errRead.Close()
	if runErr != nil {
		t.Fatalf("running through the account and stub: %v", runErr)
	}
	if code != 0 {
		t.Fatalf("stream probe ended with exit code %d", code)
	}
	if readOutErr != nil {
		t.Fatalf("reading stdout pipe: %v", readOutErr)
	}
	if readErrErr != nil {
		t.Fatalf("reading stderr pipe: %v", readErrErr)
	}
	return string(stdout), string(stderr)
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
	if len(os.Args) > 3 && os.Args[1] == slotProwlerFlag {
		os.Exit(slotProwl(os.Args[2], os.Args[3]))
	}
	if len(os.Args) > 2 && os.Args[1] == conhostProwlFlag {
		os.Exit(conhostProwl(os.Args[2]))
	}
	if len(os.Args) > 3 && os.Args[1] == slotVictimFlag {
		os.Exit(slotVictim(os.Args[2], os.Args[3]))
	}
	if len(os.Args) > 9 && os.Args[1] == teardownRunnerFlag {
		os.Exit(teardownRunner(os.Args[2], os.Args[3], os.Args[4],
			os.Args[5], os.Args[6], os.Args[7], os.Args[8], os.Args[9]))
	}
	if len(os.Args) > 2 && os.Args[1] == teardownBackgrounderFlag {
		os.Exit(teardownBackgrounder(os.Args[2]))
	}
	if len(os.Args) > 1 && os.Args[1] == teardownSlouchFlag {
		os.Exit(teardownSlouch())
	}
	// The stub subprocesses exit above and never reach this, so the promise
	// stays a property of the test process alone.
	restore := grant.IdentitiesStandAloneForTest()
	code := m.Run()
	restore()
	os.Exit(code)
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
