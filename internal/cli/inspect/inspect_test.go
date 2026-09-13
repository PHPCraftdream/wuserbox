package inspect

import (
	"strings"
	"testing"

	"wuserbox/internal/win/group"
)

func TestNameAcceptsNoArgumentOrADirectory(t *testing.T) {
	if err := Name(nil); err != nil {
		t.Errorf("without an argument: %v", err)
	}
	if err := Name([]string{t.TempDir()}); err != nil {
		t.Errorf("with a directory: %v", err)
	}
}

func TestPathNeedsExactlyOneGroup(t *testing.T) {
	for _, args := range [][]string{nil, {"a", "b"}} {
		if err := Path(args); err == nil {
			t.Errorf("%v should have been rejected", args)
		}
	}
}

func TestPathReportsAnUnknownGroup(t *testing.T) {
	err := Path([]string{group.Prefix + "not-here-00000000"})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("got %v", err)
	}
}

func TestListTakesNoArguments(t *testing.T) {
	if err := List(nil); err != nil {
		t.Errorf("plain list: %v", err)
	}
	if err := List([]string{"extra"}); err == nil {
		t.Error("an argument should have been rejected")
	}
}

func TestAuditAcceptsADepth(t *testing.T) {
	// Depth zero only looks at the drive roots, which keeps the test quick.
	if err := Audit([]string{"0"}); err != nil {
		t.Errorf("audit: %v", err)
	}
	if err := Audit([]string{"not-a-number"}); err == nil {
		t.Error("a non-numeric depth should have been rejected")
	}
	if err := Audit([]string{"1", "2"}); err == nil {
		t.Error("two arguments should have been rejected")
	}
}

func TestVersionPrintsTheRelease(t *testing.T) {
	if err := Version(nil); err != nil {
		t.Errorf("version: %v", err)
	}
	if Release == "" {
		t.Error("the release string is empty")
	}
	if err := Version([]string{"extra"}); err == nil {
		t.Error("an argument should have been rejected")
	}
}
