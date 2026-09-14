// External test package: token now imports group for group.ReadGroup, so a
// test file that is package group and also imports token would be a cycle.
package group_test

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// name for a group this test may create and delete.
const testName = group.Prefix + "selftest-0000dead"

func requireAdmin(t *testing.T) {
	t.Helper()
	if !token.IsAdmin() {
		t.Skip("creating a local group needs administrator rights")
	}
}

func TestCommentReportsAMissingGroup(t *testing.T) {
	_, exists, err := group.Comment(group.Prefix + "definitely-not-here")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("a group that was never created was reported as existing")
	}
}

func TestListReturnsOnlySandboxGroups(t *testing.T) {
	entries, err := group.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name, group.Prefix) {
			t.Errorf("List returned an unrelated group: %q", e.Name)
		}
	}
}

func TestAddNeedsAdministratorRights(t *testing.T) {
	if token.IsAdmin() {
		t.Skip("this check is about the unprivileged case")
	}
	err := group.Add(testName, `C:\nowhere`)
	if err == nil {
		_ = group.Delete(testName)
		t.Fatal("a local group was created without administrator rights")
	}
	if !strings.Contains(err.Error(), "administrator") {
		t.Errorf("unhelpful message: %v", err)
	}
}

func TestLifecycle(t *testing.T) {
	requireAdmin(t)
	const dir = `C:\projects\selftest`
	if err := group.Add(testName, dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Delete(testName) })

	comment, exists, err := group.Comment(testName)
	if err != nil || !exists {
		t.Fatalf("the new group was not found: %v", err)
	}
	if comment != dir {
		t.Errorf("the group remembers %q, want %q", comment, dir)
	}
	if err := group.SetComment(testName, dir+`2`); err != nil {
		t.Fatal(err)
	}
	if comment, _, _ := group.Comment(testName); comment != dir+`2` {
		t.Errorf("the comment was not updated, it reads %q", comment)
	}

	var listed bool
	entries, err := group.List()
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
	if err := group.Delete(testName); err != nil {
		t.Fatal(err)
	}
	if _, exists, _ := group.Comment(testName); exists {
		t.Error("the group survived deletion")
	}
}

// TestTheSharedReadGroupIsNotASandbox is the regression guard for a list that
// offered something nothing else could act on. wub-read carries the prefix
// every sandbox group carries, so listing by prefix alone showed it as a
// sandbox on every machine that had ever run init — one with no directory,
// which --explain could not explain and --rm would not remove.
func TestTheSharedReadGroupIsNotASandbox(t *testing.T) {
	if !strings.HasPrefix(group.ReadGroup, group.Prefix) {
		t.Fatal("wub-read no longer carries the prefix, so this guard is testing nothing")
	}
	if group.IsSandbox(group.ReadGroup) {
		t.Error("the shared read group is reported as a sandbox")
	}
	if !group.IsSandbox(group.Prefix + "project-d6e9a21f") {
		t.Error("an ordinary sandbox group is not reported as one")
	}
	if group.IsSandbox("Administrators") {
		t.Error("a group wuserbox never made is reported as a sandbox")
	}
	// And a real listing never carries it, whether or not it exists here.
	entries, err := group.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name == group.ReadGroup {
			t.Errorf("%s was listed as a sandbox", entry.Name)
		}
	}
}
