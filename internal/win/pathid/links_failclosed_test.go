// The two tests here are the close test for the enumerator's contract,
// driven through the two callers that act on its answer: a grant, and the
// profile copy that would otherwise open a destination with O_TRUNC. The
// enumeration is interrupted where it lives, in pathid -- FindFirstFileNameW
// has named the file asked about, and FindNextFileNameW fails with an error
// that is not the end of the list -- so both callers are held to what they
// owe when the names they were given are known to be incomplete: refuse
// before writing anything.
package pathid_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/profile"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
)

// An account no test grants anything to, so that finding its name on a path
// means somebody wrote it there.
const closeTestAccount = "S-1-5-21-1111111111-2222222222-3333333333-543211"

func hardLink(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/H", link, target).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}
}

// holdsOn reports whether the account appears anywhere in the permissions of
// path. icacls prints the path itself at the start of the first entry's
// line, and a test name embedded in a temporary directory can spell an
// account's name by accident, so that line has the path taken off it before
// it is searched.
func holdsOn(t *testing.T, path, account string) bool {
	t.Helper()
	out, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v", path, err)
	}
	for i, line := range strings.Split(string(out), "\n") {
		if i == 0 {
			line = strings.TrimPrefix(line, path)
		}
		if strings.Contains(line, account) {
			return true
		}
	}
	return false
}

// copyFixture points the config package and paths.Home at fresh temporary
// directories and writes a rules file whose profile section names
// .gitconfig, the way profile package's own tests prepare a copy.
func copyFixture(t *testing.T) (home, dest string) {
	t.Helper()
	home = t.TempDir()
	dest = filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	if err := (&config.Config{Profile: config.Entries([]string{".gitconfig"})}).Save(); err != nil {
		t.Fatal(err)
	}
	return home, dest
}

// TestAGrantRefusesWhenTheLinkEnumerationFailsPartway drives a grant through
// acl.Isolate with a real external hard link in the tree and an enumeration
// that stops with an error before it can say where the other name is. The
// refusal has to come before any list is written: a grant that went ahead
// here would permission the object behind the name the enumeration never
// reached.
func TestAGrantRefusesWhenTheLinkEnumerationFailsPartway(t *testing.T) {
	granted, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	hardLink(t, filepath.Join(granted, "secret.txt"), target)

	restore := pathid.FailNextNameForTest(errors.New("the injected enumeration failure"))
	defer restore()

	err := acl.Isolate(granted, closeTestAccount, []acl.ACE{
		{Access: acl.AccessModify, Inheritance: acl.InheritObjects | acl.InheritContainers},
	}, acl.InheritObjects|acl.InheritContainers, nil)
	if err == nil {
		t.Fatal("a grant went ahead on an enumeration that had admitted it was cut short")
	}
	if !strings.Contains(err.Error(), "--allow-links") {
		t.Errorf("the refusal does not say how to go ahead anyway: %v", err)
	}
	if !strings.Contains(err.Error(), "the injected enumeration failure") {
		t.Errorf("the refusal does not name the failure that caused it: %v", err)
	}
	if holdsOn(t, granted, closeTestAccount) {
		t.Error("the grant was written despite the refusal, so the tree was left changed")
	}
	if holdsOn(t, target, closeTestAccount) {
		t.Error("the file outside the tree was reached despite the refusal")
	}
}

// TestACopyRefusesWhenTheLinkEnumerationFailsPartway drives the profile copy
// with a destination whose names all stay inside the profile -- the case
// that must keep working -- and an enumeration that stops with an error
// before it can say whether they do. The copy has to refuse before opening
// the destination: O_TRUNC on a name whose other names are unknown can reach
// a file outside the profile through the name that was never listed.
func TestACopyRefusesWhenTheLinkEnumerationFailsPartway(t *testing.T) {
	home, dest := copyFixture(t)
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("source contents\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dest, "alias.txt")
	if err := os.WriteFile(alias, []byte("old contents\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hardLink(t, filepath.Join(dest, ".gitconfig"), alias)

	restore := pathid.FailNextNameForTest(errors.New("the injected enumeration failure"))
	_, _, err := profile.Copy(dest, nil, nil)
	restore()
	if err == nil {
		t.Fatal("a copy went ahead on an enumeration that had admitted it was cut short")
	}
	if !strings.Contains(err.Error(), "external hard links") {
		t.Errorf("the refusal does not say the destination's names could not be checked: %v", err)
	}
	if !strings.Contains(err.Error(), "the injected enumeration failure") {
		t.Errorf("the refusal does not name the failure that caused it: %v", err)
	}
	kept, readErr := os.ReadFile(alias)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(kept) != "old contents\n" {
		t.Errorf("the copy reached the file whose names it could not all read: %q", kept)
	}

	// The control: the very same destination, enumerated for real -- every
	// name found and the list ended the documented way -- goes through.
	if _, _, err := profile.Copy(dest, nil, nil); err != nil {
		t.Fatalf("the same copy was refused once the enumeration could finish: %v", err)
	}
	kept, readErr = os.ReadFile(alias)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(kept) != "source contents\n" {
		t.Errorf("the internal hard-link alias did not receive the copy: %q", kept)
	}
}
