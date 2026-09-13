package group

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// name for a group this test may create and delete.
const testName = Prefix + "selftest-0000dead"

func requireAdmin(t *testing.T) {
	t.Helper()
	if !token.IsAdmin() {
		t.Skip("creating a local group needs administrator rights")
	}
}

func TestCommentReportsAMissingGroup(t *testing.T) {
	_, exists, err := Comment(Prefix + "definitely-not-here")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("a group that was never created was reported as existing")
	}
}

func TestListReturnsOnlySandboxGroups(t *testing.T) {
	entries, err := List()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name, Prefix) {
			t.Errorf("List returned an unrelated group: %q", e.Name)
		}
	}
}

func TestAddNeedsAdministratorRights(t *testing.T) {
	if token.IsAdmin() {
		t.Skip("this check is about the unprivileged case")
	}
	err := Add(testName, `C:\nowhere`)
	if err == nil {
		_ = Delete(testName)
		t.Fatal("a local group was created without administrator rights")
	}
	if !strings.Contains(err.Error(), "administrator") {
		t.Errorf("unhelpful message: %v", err)
	}
}

func TestLifecycle(t *testing.T) {
	requireAdmin(t)
	const dir = `C:\projects\selftest`
	if err := Add(testName, dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Delete(testName) })

	comment, exists, err := Comment(testName)
	if err != nil || !exists {
		t.Fatalf("the new group was not found: %v", err)
	}
	if comment != dir {
		t.Errorf("the group remembers %q, want %q", comment, dir)
	}
	if err := SetComment(testName, dir+`2`); err != nil {
		t.Fatal(err)
	}
	if comment, _, _ := Comment(testName); comment != dir+`2` {
		t.Errorf("the comment was not updated, it reads %q", comment)
	}

	var listed bool
	entries, err := List()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name == testName {
			listed = true
		}
	}
	if !listed {
		t.Error("the new group is missing from the list")
	}
	if err := Delete(testName); err != nil {
		t.Fatal(err)
	}
	if _, exists, _ := Comment(testName); exists {
		t.Error("the group survived deletion")
	}
}
