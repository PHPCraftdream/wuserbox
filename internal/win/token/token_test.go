package token

import (
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

const unusedGroup = "S-1-5-21-1111111111-2222222222-3333333333-543210"

func TestRestrictedBuildsForAnyGroup(t *testing.T) {
	restricted, err := Restricted(unusedGroup)
	if err != nil {
		t.Fatalf("building the sandbox token: %v", err)
	}
	defer restricted.Close()
	if restricted == 0 {
		t.Error("got an empty token handle")
	}
}

func TestRestrictedRejectsNonsenseGroups(t *testing.T) {
	if _, err := Restricted("not-a-sid"); err == nil {
		t.Error("expected an error")
	}
}

func TestThisProcessIsNotSandboxed(t *testing.T) {
	// The test binary runs normally, so the flag must be off. The sandboxed
	// case is covered end to end, where a real restricted token is in play.
	if IsRestricted() {
		t.Error("the test process reports itself as sandboxed")
	}
}

func TestIsAdminAnswers(t *testing.T) {
	// Either answer is correct; the call must simply work.
	_ = IsAdmin()
}

// The three identifiers restrict parses -- the sandbox's group, Everyone and
// Users -- are system memory for exactly as long as CreateRestrictedToken
// takes to copy them into the token it builds, and the collector does not own
// them: a build that kept them would grow native memory with every token it
// made, and one that stopped partway would keep whatever it had parsed by
// then. A nonsense read group is handed in on purpose -- a sandbox may run
// without one, and the lookup's refusal is tolerated mid-build.
func TestRestrictGivesBackTheIdentifiersItParses(t *testing.T) {
	self, err := ownToken()
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()

	parses, frees := sid.Parses(), sid.Frees()
	for i := 0; i < 2; i++ {
		restricted, err := restrict(self, unusedGroup, "not-a-group", false)
		if err != nil {
			t.Fatalf("building the restricted token: %v", err)
		}
		restricted.Close()
	}
	if got := sid.Parses() - parses; got != 6 {
		t.Errorf("two builds parsed %d identifiers, want three each", got)
	}
	if got := sid.Frees() - frees; got != 6 {
		t.Errorf("two builds gave %d identifiers back, want all six parsed", got)
	}
}

// A group no identifier answers to stops the build before the first parse,
// so the error has nothing to give back and must leave nothing behind.
func TestRestrictParsesNothingWhenTheGroupIsRefused(t *testing.T) {
	self, err := ownToken()
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()

	parses, frees := sid.Parses(), sid.Frees()
	if _, err := restrict(self, "not-a-sid", "not-a-group", false); err == nil {
		t.Fatal("a group no identifier answers to built a token anyway")
	}
	if got := sid.Parses() - parses; got != 0 {
		t.Errorf("the refused build parsed %d identifiers, want none", got)
	}
	if got := sid.Frees() - frees; got != 0 {
		t.Errorf("the refused build freed %d identifiers, want none", got)
	}
}
