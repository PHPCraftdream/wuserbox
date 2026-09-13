package sid

import (
	"strings"
	"testing"
)

func TestParseAcceptsWellKnownIdentifiers(t *testing.T) {
	for _, text := range []string{Everyone, System, "S-1-5-32-544"} {
		if _, err := Parse(text); err != nil {
			t.Errorf("Parse(%q): %v", text, err)
		}
	}
}

func TestParseRejectsNonsense(t *testing.T) {
	for _, text := range []string{"", "not-a-sid", "S-1-", "12345"} {
		if _, err := Parse(text); err == nil {
			t.Errorf("Parse(%q) should have failed", text)
		}
	}
}

func TestLookupResolvesABuiltInGroup(t *testing.T) {
	value, err := Lookup("Administrators")
	if err != nil {
		t.Skipf("Administrators is not resolvable here: %v", err)
	}
	if got := value.String(); got != "S-1-5-32-544" {
		t.Errorf("Administrators resolved to %q", got)
	}
}

func TestLookupReportsUnknownAccounts(t *testing.T) {
	if _, err := Lookup("wuserbox-no-such-account"); err == nil {
		t.Error("expected an error")
	}
}

func TestEmptyValueFormatsAsEmptyString(t *testing.T) {
	if got := Value(nil).String(); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestCurrentUserLooksLikeAnAccount(t *testing.T) {
	got, err := CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "S-1-5-21-") {
		t.Errorf("current user resolved to %q", got)
	}
}
