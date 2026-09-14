package token

import "testing"

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
