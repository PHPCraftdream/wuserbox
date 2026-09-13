package access

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

const testGroup = "S-1-5-21-1111111111-2222222222-3333333333-909090"

func TestParseAcceptsTheFourOperations(t *testing.T) {
	for _, word := range []string{"read", "write", "create", "delete"} {
		if _, err := Parse(word); err != nil {
			t.Errorf("%s: %v", word, err)
		}
	}
	if _, err := Parse("rename"); err == nil {
		t.Error("an unknown operation should be rejected")
	}
}

// prepared returns a directory the test group may write to, and one it may not.
func prepared(t *testing.T) (granted, denied string) {
	t.Helper()
	root := t.TempDir()
	granted, denied = filepath.Join(root, "granted"), filepath.Join(root, "denied")
	for _, dir := range []string{granted, denied} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := grant.Apply(testGroup, granted, grant.RW); err != nil {
		t.Fatal(err)
	}
	return granted, denied
}

func TestCheckFollowsThePermissions(t *testing.T) {
	granted, denied := prepared(t)
	for _, file := range []string{filepath.Join(granted, "f.txt"), filepath.Join(denied, "f.txt")} {
		if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		path      string
		operation Operation
		want      bool
	}{
		{filepath.Join(granted, "f.txt"), Write, true},
		{filepath.Join(granted, "f.txt"), Delete, true},
		{filepath.Join(granted, "new.txt"), Create, true},
		{filepath.Join(denied, "f.txt"), Write, false},
		{filepath.Join(denied, "f.txt"), Delete, false},
		{filepath.Join(denied, "new.txt"), Create, false},
		{filepath.Join(denied, "f.txt"), Read, true}, // reading is not restricted
	}
	for _, c := range cases {
		result, err := Check(testGroup, c.path, c.operation)
		if err != nil {
			t.Errorf("%s %s: %v", c.operation, c.path, err)
			continue
		}
		if result.Allowed != c.want {
			t.Errorf("%s %s: allowed=%v, want %v (%s)",
				c.operation, c.path, result.Allowed, c.want, result.Reason)
		}
		if result.Reason == "" {
			t.Errorf("%s %s: no reason given", c.operation, c.path)
		}
	}
}

func TestCheckAnswersAboutTheParentWhenCreating(t *testing.T) {
	granted, _ := prepared(t)
	missing := filepath.Join(granted, "not-there-yet.txt")
	result, err := Check(testGroup, missing, Create)
	if err != nil {
		t.Fatal(err)
	}
	if result.Checked != granted {
		t.Errorf("the question was asked about %s, want %s", result.Checked, granted)
	}
	if !result.Allowed {
		t.Errorf("creating in a writable directory was refused: %s", result.Reason)
	}
}

func TestCheckReportsAMissingPath(t *testing.T) {
	granted, _ := prepared(t)
	if _, err := Check(testGroup, filepath.Join(granted, "absent"), Write); err == nil {
		t.Error("expected an error for a path that does not exist")
	}
}

func TestCheckChangesNothing(t *testing.T) {
	granted, denied := prepared(t)
	before, err := os.ReadDir(granted)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range Operations {
		_, _ = Check(testGroup, filepath.Join(granted, "probe.txt"), operation)
		_, _ = Check(testGroup, denied, operation)
	}
	after, err := os.ReadDir(granted)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("asking created something: %d entries, was %d", len(after), len(before))
	}
}

func TestCheckAgreesWithARealWrite(t *testing.T) {
	// The answer is only worth anything if it matches what happens.
	granted, denied := prepared(t)
	if err := acl.Protect(filepath.Join(denied)); err != nil {
		t.Fatal(err)
	}
	allowed, err := Check(testGroup, granted, Create)
	if err != nil {
		t.Fatal(err)
	}
	refused, err := Check(testGroup, denied, Create)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Allowed || refused.Allowed {
		t.Errorf("granted=%v denied=%v", allowed.Allowed, refused.Allowed)
	}
}
