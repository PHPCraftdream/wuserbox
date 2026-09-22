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

// The replacement decision is the one place an init can take a live account
// away, so both directions of it are pinned without touching the machine:
// ownerOf stands in for the accounts database and the deletions are
// counted, never made. The group and project are the same in every case --
// that is exactly the situation the decision exists for: one project whose
// group and account two operators arrive at, each from a record of their
// own, and only the recorded creator can tell the accounts apart.
func TestReplaceAccountAsksItsOwnerFirst(t *testing.T) {
	const (
		groupName = "wub-owner-decision-deadbeef"
		account   = "wub-0e5e1dea"
		mine      = "S-1-5-21-3623811015-3361044348-30300820-1001"
		theirs    = "S-1-5-21-3623811015-3361044348-30300820-2002"
	)
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if err := os.MkdirAll(ProfileDir(groupName), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name         string
		recorded     string
		ownerErr     error
		exists       bool
		wantDeletion bool
		wantInErr    []string
	}{
		{
			name:      "another operator's account is left standing",
			recorded:  theirs,
			exists:    true,
			wantInErr: []string{"another operator", theirs},
		},
		{
			name:      "an account recording no creator is left standing",
			recorded:  "",
			exists:    true,
			wantInErr: []string{"no operator"},
		},
		{
			name:      "an owner that cannot be read stops the init",
			ownerErr:  fmt.Errorf("accounts database unavailable"),
			exists:    true,
			wantInErr: []string{"cannot read who created"},
		},
		{
			name:      "an account that vanishes before the read is not deleted",
			exists:    false,
			wantInErr: []string{"refusing to delete"},
		},
		{
			name:         "the operator's own lost record is replaced",
			recorded:     mine,
			exists:       true,
			wantDeletion: true,
		},
		{
			name:         "the operator's own account spelled differently is still theirs",
			recorded:     strings.ToUpper(mine),
			exists:       true,
			wantDeletion: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var deleted []string
			s := &state.State{Account: account}
			err := replaceAccountTheOperatorOwns(s, account, groupName, mine,
				func(string) (string, bool, error) { return tc.recorded, tc.exists, tc.ownerErr },
				func(name string) error { deleted = append(deleted, name); return nil },
			)
			if tc.wantDeletion {
				if err != nil {
					t.Fatalf("the operator's own account was not replaced: %v", err)
				}
				if len(deleted) != 1 || deleted[0] != account {
					t.Fatalf("one replacement of %s was expected, got %v", account, deleted)
				}
				if s.Account != "" {
					t.Errorf("the record still names %q after the replacement", s.Account)
				}
				if _, err := os.Stat(ProfileDir(groupName)); !os.IsNotExist(err) {
					t.Errorf("the profile outlived the replacement: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("an account the operator does not own was taken away without a word")
			}
			if len(deleted) != 0 {
				t.Fatalf("the refusal came after deleting %v; it has to come before", deleted)
			}
			if s.Account != account {
				t.Errorf("a refused replacement still cleared the record: %q", s.Account)
			}
			for _, want := range tc.wantInErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal says %q, want it to name %q", err, want)
				}
			}
		})
	}
}

// The classification behind the refusal table above, one row per answer,
// including the pair of empty strings that means neither side of the
// question could be established at all.
func TestClassifyOwner(t *testing.T) {
	const (
		mine   = "S-1-5-21-1-2-3-1001"
		theirs = "S-1-5-21-1-2-3-2002"
	)
	for _, tc := range []struct {
		recorded, operator string
		want               ownerProof
	}{
		{mine, mine, ownerSelf},
		{strings.ToUpper(mine), mine, ownerSelf},
		{theirs, mine, ownerForeign},
		{mine, theirs, ownerForeign},
		{"", mine, ownerUnestablished},
		{"", "", ownerUnestablished},
	} {
		if got := classifyOwner(tc.recorded, tc.operator); got != tc.want {
			t.Errorf("classifyOwner(%q, %q) = %v, want %v", tc.recorded, tc.operator, got, tc.want)
		}
	}
}

// Both fixtures below walk the real path replaceUnopenableAccount walks --
// a real group, a real account, the real membership and comment lookups --
// because the decision table above proves the seam, not the wiring. They
// need administrator rights the same as the collision test beside them, and
// skip without them.

func currentSID(t *testing.T) string {
	t.Helper()
	value, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestInitRefusesToReplaceAnotherOperatorsUnopenableAccount(t *testing.T) {
	if !token.IsAdmin() {
		t.Skip("the unopenable-account fixture needs administrator rights")
	}
	tag := strconv.FormatInt(time.Now().UnixNano(), 16)
	groupName := fmt.Sprintf("%sforeign-%s-deadbeef", group.Prefix, tag)
	dir := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := group.Add(groupName, dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Delete(groupName) })

	stranger := "S-1-5-21-3623811015-3361044348-30300820-2026"
	name := acct.NameFor(groupName)
	password, err := acct.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := acct.Add(name, acct.OwnerComment(dir, stranger), password); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = acct.Delete(name) })
	if err := acct.EnsureMembership(name, groupName); err != nil {
		t.Fatal(err)
	}

	s := &state.State{}
	err = replaceUnopenableAccount(s, name, groupName, dir, currentSID(t))
	if err == nil {
		t.Fatal("an account another operator created was replaced without a word")
	}
	if _, err := sid.Lookup(name); err != nil {
		t.Fatalf("the stranger's account was taken away anyway: %v", err)
	}
	if s.Account != "" {
		t.Errorf("a refused replacement wrote to the record: %q", s.Account)
	}
}

func TestInitStillReplacesTheOperatorsOwnUnopenableAccount(t *testing.T) {
	if !token.IsAdmin() {
		t.Skip("the unopenable-account fixture needs administrator rights")
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	tag := strconv.FormatInt(time.Now().UnixNano(), 16)
	groupName := fmt.Sprintf("%srecovery-%s-deadbeef", group.Prefix, tag)
	dir := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := group.Add(groupName, dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Delete(groupName) })

	name := acct.NameFor(groupName)
	password, err := acct.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := acct.Add(name, acct.OwnerComment(dir, currentSID(t)), password); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = acct.Delete(name) })
	if err := acct.EnsureMembership(name, groupName); err != nil {
		t.Fatal(err)
	}
	profile := ProfileDir(groupName)
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}

	s := &state.State{}
	if err := replaceUnopenableAccount(s, name, groupName, dir, currentSID(t)); err != nil {
		t.Fatalf("the operator's own lost record was not recovered: %v", err)
	}
	if _, err := sid.Lookup(name); err == nil {
		t.Fatal("the account survived its replacement")
	}
	if s.Account != "" {
		t.Errorf("the replacement left %q in the record", s.Account)
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Errorf("the thin profile outlived the account it belongs to: %v", err)
	}
}
