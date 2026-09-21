package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	acct "github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/quietexec"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// TestArgsCarriesTheDashThatMarksACommand is the regression guard for a
// rebuilt command line that named the command but not as one. Elevate re-runs
// wuserbox with these arguments as a brand new process, and a first word
// without a dash is read as a program to run, not as init: the elevated copy
// would have gone looking for a program called "init" instead of building the
// sandbox.
func TestArgsCarriesTheDashThatMarksACommand(t *testing.T) {
	args := Options{Dir: `C:\project`, RW: []string{`C:\extra`}, NoAI: true, AllowLinks: true}.Args()
	if len(args) == 0 || args[0] != "--init" {
		t.Fatalf("the command line starts with %q, want \"--init\"", args)
	}
	if !strings.Contains(strings.Join(args, " "), `--dir C:\project`) {
		t.Errorf("the project directory is missing: %v", args)
	}
	if !strings.Contains(strings.Join(args, " "), `--allow-links`) {
		t.Errorf("the link policy is missing from the elevated command line: %v", args)
	}
}

// TestInitRefusesAnExternalHardLinkBeforeChangingItsACL is the preflight
// guard for the privileged profile builder. ValidateLinks must run before
// MakeProfile applies an inheritable ACL to the profile root: an external
// hard-link name is the same file object, so changing the profile can change
// the supposedly unrelated file outside it.
func TestInitRefusesAnExternalHardLinkBeforeChangingItsACL(t *testing.T) {
	if !token.IsAdmin() {
		t.Skip("the init profile preflight needs administrator rights")
	}

	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)
	groupName := fmt.Sprintf("%spreflight-%x", group.Prefix, time.Now().UnixNano())
	accountName := acct.NameFor(groupName)
	password, err := acct.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	profile := ProfileDir(groupName)
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("must remain"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(profile, "NTUSER.DAT")
	if err := os.Link(outside, linked); err != nil {
		t.Skipf("hard links unavailable on this volume: %v", err)
	}

	if err := acct.Add(accountName, profile, password); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = acct.Delete(accountName) })
	value, err := sid.Lookup(accountName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = acct.DeleteProfile(value.String())
		_ = acct.RemoveProfileServiceReference(value)
	})

	before := icaclsText(t, outside)
	err = ensureProfile(&state.State{Account: accountName}, groupName)
	if err == nil {
		t.Fatal("init accepted a profile with a hard link outside it")
	}
	if after := icaclsText(t, outside); after != before {
		t.Fatalf("init changed the external hard-link target's ACL before refusing the profile\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func icaclsText(t *testing.T, path string) string {
	t.Helper()
	out, err := quietexec.Command("icacls", path).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v\n%s", path, err, out)
	}
	return string(out)
}

func TestAccountCollisionRefusesReplacementOfAnotherSandbox(t *testing.T) {
	if !token.IsAdmin() {
		t.Skip("account collision fixture needs administrator rights")
	}
	tag := strconv.FormatInt(time.Now().UnixNano(), 16)
	firstGroup := fmt.Sprintf("%sidentity-a-%s-deadbeef", group.Prefix, tag)
	secondGroup := fmt.Sprintf("%sidentity-b-%s-deadbeef", group.Prefix, tag)
	firstDir := filepath.Join(t.TempDir(), "first")
	secondDir := filepath.Join(t.TempDir(), "second")
	if err := os.Mkdir(firstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(secondDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := group.Add(firstGroup, firstDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Delete(firstGroup) })
	if err := group.Add(secondGroup, secondDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Delete(secondGroup) })

	legacyAccount := acct.LegacyNameFor(firstGroup)
	password, err := acct.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := acct.Add(legacyAccount, firstDir, password); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = acct.Delete(legacyAccount) })
	if err := acct.EnsureMembership(legacyAccount, firstGroup); err != nil {
		t.Fatal(err)
	}

	s := &state.State{}
	if _, err := accountName(s, secondGroup, secondDir); err == nil {
		t.Fatal("colliding account was accepted for the second sandbox")
	}
	if _, err := sid.Lookup(legacyAccount); err != nil {
		t.Fatalf("collision guard lost the first sandbox account: %v", err)
	}
}

// TestArgsCarriesTheOutputFlags is the regression guard for the elevated copy
// losing the output mode. A --quiet or --json run that had to ask for
// administrator rights handed the elevated init neither flag, and the copy --
// which inherits nothing from this process -- went back to progress prose and
// plain lines in a console of its own.
func TestArgsCarriesTheOutputFlags(t *testing.T) {
	args := Options{Dir: `C:\project`, Quiet: true, JSON: true}.Args()
	joined := strings.Join(args, " ")
	for _, flag := range []string{"--quiet", "--json"} {
		if !strings.Contains(joined, flag) {
			t.Errorf("the output flag %s is missing from the elevated command line: %v", flag, args)
		}
	}
	// And a run that asked for neither must not find them on the line.
	plain := strings.Join(Options{Dir: `C:\project`}.Args(), " ")
	for _, flag := range []string{"--quiet", "--json"} {
		if strings.Contains(plain, flag) {
			t.Errorf("%s travels on an init that never asked for it: %v", flag, plain)
		}
	}
}
