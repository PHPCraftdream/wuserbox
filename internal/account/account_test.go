package account

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// testGroup and testName name the local group and account this test may
// create and delete. Unmistakable on purpose, the way group's own selftest
// name is: nothing else on a real machine should ever be named either of
// these.
const (
	testGroup = group.Prefix + "acct-selftest-0000dead"
	testName  = Prefix + "slftstdead" // 10 characters after "wub-": well under 20
)

func requireAdmin(t *testing.T) {
	t.Helper()
	if !token.IsAdmin() {
		t.Skip("creating a local account needs administrator rights")
	}
}

func TestNameForKeepsOnlyTheTrailingHash(t *testing.T) {
	groupName := group.Prefix + "my-great-project-a1b2c3d4"
	got := NameFor(groupName)
	if len(got) > 20 {
		t.Errorf("NameFor(%q) = %q, %d characters: NetUserAdd caps a name at 20", groupName, got, len(got))
	}
	if !strings.HasSuffix(got, "a1b2c3d4") {
		t.Errorf("NameFor(%q) = %q, lost the hash that keeps two projects apart", groupName, got)
	}
	if got == groupName {
		t.Errorf("NameFor(%q) returned the group's own name: an account cannot share it", groupName)
	}
}

func TestNameForNeverCollidesWithItsGroup(t *testing.T) {
	// Every real group name carries a slug and a separating hyphen before
	// the hash -- slug() falls back to "root" rather than leaving it empty
	// -- so an account name, which drops the slug entirely, is always
	// shorter than any group name sandbox.Name actually produces.
	for _, groupName := range []string{
		group.Prefix + "root-deadbeef",
		group.Prefix + "a-deadbeef",
	} {
		if NameFor(groupName) == groupName {
			t.Errorf("NameFor(%q) collided with its own group name", groupName)
		}
	}
	// A name with nothing but the hash after the prefix -- shorter than any
	// group name can be, and shorter than or equal to hashLen -- takes the
	// fallback branch and is returned unchanged with the prefix repeated,
	// which is fine: sandbox.Name never produces anything this short.
	if got := NameFor(group.Prefix + "dead"); got != group.Prefix+group.Prefix+"dead" {
		t.Errorf("NameFor of a too-short name changed shape unexpectedly: got %q", got)
	}
}

func TestNameForSeparatesGroupsWithTheSameLegacySuffix(t *testing.T) {
	first := group.Prefix + "first-project-deadbeef"
	second := group.Prefix + "second-project-deadbeef"
	if LegacyNameFor(first) != LegacyNameFor(second) {
		t.Fatal("fixture does not share the legacy account identity")
	}
	if NameFor(first) == NameFor(second) {
		t.Fatalf("current account identities still collide: %q", NameFor(first))
	}
	if len(NameFor(first)) != 20 || len(NameFor(second)) != 20 {
		t.Fatalf("current account name exceeds or misses the Windows limit: %q, %q", NameFor(first), NameFor(second))
	}
}

func TestGeneratePasswordMeetsWindowsComplexity(t *testing.T) {
	password, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(password) < 14 {
		t.Errorf("password is %d characters, shorter than a common minimum policy", len(password))
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSymbol {
		t.Errorf("password %q does not carry all four character classes", password)
	}
}

func TestGeneratePasswordDoesNotRepeatItself(t *testing.T) {
	first, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("two generated passwords were identical")
	}
}

func TestProtectAndUnprotectRoundTrips(t *testing.T) {
	const password = `tr0ub4dor&3!QUICK`
	sealed, err := Protect(password)
	if err != nil {
		t.Fatal(err)
	}
	if sealed == password {
		t.Error("the sealed value is the plain password")
	}
	opened, err := Unprotect(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if opened != password {
		t.Errorf("got %q back, want %q", opened, password)
	}
}

func TestUnprotectRejectsGarbage(t *testing.T) {
	if _, err := Unprotect("not-valid-base64-!!!"); err == nil {
		t.Error("expected an error decoding nonsense")
	}
	if _, err := Unprotect("dGhpcyBpcyBub3QgYSBzZWFsZWQgYmxvYg=="); err == nil {
		t.Error("expected an error unsealing bytes DPAPI never sealed")
	}
}

func TestAddNeedsAdministratorRights(t *testing.T) {
	if token.IsAdmin() {
		t.Skip("this check is about the unprivileged case")
	}
	err := Add(testName, `C:\nowhere`, "wH4tever-Pwd1")
	if err == nil {
		_ = Delete(testName)
		t.Fatal("a local account was created without administrator rights")
	}
	if !strings.Contains(err.Error(), "administrator") {
		t.Errorf("unhelpful message: %v", err)
	}
}

func TestLifecycle(t *testing.T) {
	requireAdmin(t)
	const dir = `C:\projects\selftest`

	if err := group.Add(testGroup, dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Delete(testGroup) })

	password, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := Add(testName, dir, password); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Delete(testName) })

	if _, err := sid.Lookup(testName); err != nil {
		t.Fatalf("the new account was not found: %v", err)
	}

	builtinUsers, err := BuiltinUsersName()
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureMembership(testName, testGroup, builtinUsers); err != nil {
		t.Fatal(err)
	}
	// Idempotent: running it again over memberships already held must not
	// be reported as a failure.
	if err := EnsureMembership(testName, testGroup, builtinUsers); err != nil {
		t.Fatalf("re-asserting the same memberships failed: %v", err)
	}

	members, err := Members(testGroup)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, m := range members {
		if strings.EqualFold(m, testName) {
			found = true
		}
	}
	if !found {
		t.Errorf("the account is not listed among %s's members: %v", testGroup, members)
	}

	if err := HideFromSignIn(testName); err != nil {
		t.Fatal(err)
	}
	if err := UnhideFromSignIn(testName); err != nil {
		t.Fatal(err)
	}
	// A value that was never there is not an error either.
	if err := UnhideFromSignIn(testName); err != nil {
		t.Errorf("un-hiding an already-unhidden account failed: %v", err)
	}

	if err := DenyRemoteLogon(testName); err != nil {
		t.Fatal(err)
	}

	value, err := sid.Lookup(testName)
	if err != nil {
		t.Fatal(err)
	}

	profileDir := filepath.Join(t.TempDir(), "profile")
	if err := MakeProfile(profileDir, value); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(profileDir, "NTUSER.DAT")); err != nil {
		t.Errorf("no hive was made under the profile: %v", err)
	}
	for _, sub := range []string{`AppData\Local`, `AppData\Roaming`, "Temp"} {
		if info, err := os.Stat(filepath.Join(profileDir, sub)); err != nil || !info.IsDir() {
			t.Errorf("%s was not made under the profile: %v", sub, err)
		}
	}
	// Idempotent: a second call over the same profile must not fail or try
	// to re-tighten a hive that is already tightened.
	if err := MakeProfile(profileDir, value); err != nil {
		t.Errorf("re-making an existing profile failed: %v", err)
	}
	if err := RegisterProfile(value, profileDir); err != nil {
		t.Fatal(err)
	}
	// Clearing a reference the profile service never made, because the
	// account this test built never actually logged on, is not an error.
	if err := RemoveProfileServiceReference(value); err != nil {
		t.Errorf("clearing a profile service reference that may never have existed: %v", err)
	}

	// This account never logged on, so it has no profile of Windows' own
	// making: DeleteProfile must say so by doing nothing, not by failing.
	// It still clears the ProfileList entry RegisterProfile just wrote.
	if err := DeleteProfile(value.String()); err != nil {
		t.Errorf("deleting a profile that was never made: %v", err)
	}
	// And it is actually gone. Reporting success while the entry still
	// stands is what this looked like before: Windows would go on believing
	// a deleted account has a profile at a path nothing has cleaned up.
	if hasProfile(value.String()) {
		t.Error("the ProfileList entry survived DeleteProfile")
	}

	if err := Delete(testName); err != nil {
		t.Fatal(err)
	}
	if _, err := sid.Lookup(testName); err == nil {
		t.Error("the account survived deletion")
	}
}

// Unlike TestLifecycle this needs no administrator rights, because the case
// it is about is the run that does not have them: making the hive needs
// none and narrowing its permissions needs two, so an ordinary run gets
// through the first half and stops in the second. What it must not leave is
// a hive at the name MakeProfile reads to decide the profile is already
// built -- that one still grants Everyone full control, and no later run,
// however privileged, would look at it again.
func TestAHalfMadeProfileLeavesNoHiveForTheNextRunToTrust(t *testing.T) {
	users, err := BuiltinUsersName()
	if err != nil {
		t.Fatal(err)
	}
	value, err := sid.Lookup(users)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "profile")
	hive := filepath.Join(dir, "NTUSER.DAT")
	if err := MakeProfile(dir, value); err != nil {
		if _, stat := os.Stat(hive); stat == nil {
			t.Fatalf("MakeProfile stopped at %v and still left %s where the next run reads it", err, hive)
		}
		return
	}
	if _, err := os.Stat(hive); err != nil {
		t.Fatalf("MakeProfile finished without making a hive: %v", err)
	}
	if _, err := os.Stat(hive + ".partial"); err == nil {
		t.Error("the half-made hive was left beside the finished one")
	}
}

// What decides whether a process may raise its own privileges. A prefix
// alone is not enough to decide it on: the whole name has to be the shape
// NameFor builds, or an account somebody else called wub-something would be
// treated as a sandbox, and -- far worse in the other direction -- a real
// sandbox account spelled in a way this does not recognize would be allowed
// to ask for administrator rights.
func TestOnlyAnAccountShapedLikeOneWeMadeCountsAsOne(t *testing.T) {
	for _, groupName := range []string{"wub-project-deadbeef", "wub-a_b.c-0123abcd", "wub-x-ffffffff"} {
		if name := NameFor(groupName); !Own(name) {
			t.Errorf("%s, which NameFor just built from %s, is not recognized as ours", name, groupName)
		}
	}
	// Windows compares account names without regard to case, so the same
	// account can come back spelled either way and must still be known.
	if !Own("WUB-DEADBEEF") {
		t.Error("an account of ours spelled in upper case was not recognized")
	}
	for _, other := range []string{
		"Computer", "administrator", "",
		"wub-read",      // the shared read group, never an account
		"wub-",          // prefix and nothing else
		"wub-deadbee",   // one short
		"wub-deadbeef1", // one long
		"wub-notahexx",  // right length, not hex
		"awub-deadbeef", // prefix, but not at the front
	} {
		if Own(other) {
			t.Errorf("%q was taken for an account we made", other)
		}
	}
}
