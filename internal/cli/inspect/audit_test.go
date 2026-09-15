package inspect

import (
	"os"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// TestAFindingSaysWhichAnswerItIs is the regression guard for a list that
// printed two different answers the same way.
//
// A directory open to Everyone and a directory whose permissions this account
// may not read are not the same finding, and the second one landed on the
// worst possible entries: measured on an ordinary machine, --audit named two
// other people's profiles as writable by Everyone and by Users, because their
// lists are closed to everybody and an unreadable list counts as writable.
func TestAFindingSaysWhichAnswerItIs(t *testing.T) {
	open := finding(`C:\ProgramData\something`, []string{"Everyone", "Users"})
	if !strings.Contains(open, "Everyone, Users") {
		t.Errorf("a directory open to both does not say so: %s", open)
	}
	if strings.Contains(open, "could not be read") {
		t.Errorf("a directory that was read claims it was not: %s", open)
	}

	// A deliberately dull path. The real one this was found on is
	// C:\Users\<somebody>, which carries one of the identity names inside it,
	// so a test written with that path would have caught its own path rather
	// than the answer -- as this one did, first time round.
	silent := finding(`D:\closed`, nil)
	if !strings.Contains(silent, "could not be read") {
		t.Errorf("a list that could not be read does not say so: %s", silent)
	}
	if strings.Contains(silent, "Everyone") || strings.Contains(silent, "Users") {
		t.Errorf("a list that could not be read named an identity anyway: %s", silent)
	}
}

// TestAnOrdinaryDirectoryIsReadable keeps the new test from crying wolf: if
// everything counted as unreadable, the line above would be the only one
// anybody ever saw.
func TestAnOrdinaryDirectoryIsReadable(t *testing.T) {
	dir := t.TempDir()
	if acl.Unreadable(dir) {
		t.Errorf("a directory this account just made is reported as one it cannot read: %s", dir)
	}
	if acl.Unreadable(os.Getenv("SystemRoot")) {
		t.Error("the Windows directory is reported as one this account cannot read")
	}
}
