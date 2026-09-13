package acl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

const unusedAccount = "S-1-5-21-1111111111-2222222222-3333333333-543210"

func TestEveryoneWritableSeesAPermission(t *testing.T) {
	dir := t.TempDir()
	if EveryoneWritable(dir) {
		t.Fatalf("a fresh temp directory should not be writable by Everyone: %s", dir)
	}
	if err := Set(dir, sid.Everyone, []ACE{{Access: AccessModify, Inheritance: InheritObjects | InheritContainers}}); err != nil {
		t.Fatal(err)
	}
	if !EveryoneWritable(dir) {
		t.Error("the permission for Everyone was not noticed")
	}
	if err := Remove(dir, sid.Everyone); err != nil {
		t.Fatal(err)
	}
	if EveryoneWritable(dir) {
		t.Error("the permission survived removal")
	}
}

func TestEveryoneWritableIgnoresReadOnlyPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := Set(dir, sid.Everyone, []ACE{{Access: AccessReadExecute, Inheritance: InheritObjects}}); err != nil {
		t.Fatal(err)
	}
	if EveryoneWritable(dir) {
		t.Error("a read-only permission was reported as writable")
	}
}

func TestSetNeedsEntries(t *testing.T) {
	if err := Set(t.TempDir(), unusedAccount, nil); err == nil {
		t.Error("expected an error when no entries are given")
	}
}

func TestSetIsRepeatable(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := Set(dir, unusedAccount, []ACE{{Access: AccessModify, Inheritance: InheritObjects}}); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := Remove(dir, unusedAccount); err != nil {
		t.Fatal(err)
	}
	if err := Remove(dir, unusedAccount); err != nil {
		t.Errorf("removing twice should be harmless: %v", err)
	}
}

func TestCallsReportAMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	if err := Set(missing, unusedAccount, []ACE{{Access: AccessModify}}); err == nil {
		t.Error("Set should fail for a path that does not exist")
	}
	if err := Deny(missing, unusedAccount, AccessModify); err == nil {
		t.Error("Deny should fail for a path that does not exist")
	}
	if err := Protect(missing); err == nil {
		t.Error("Protect should fail for a path that does not exist")
	}
}

func TestCallsRejectNonsenseAccounts(t *testing.T) {
	dir := t.TempDir()
	if err := Set(dir, "not-a-sid", []ACE{{Access: AccessModify}}); err == nil {
		t.Error("Set should reject a malformed account")
	}
	if err := Remove(dir, "not-a-sid"); err == nil {
		t.Error("Remove should reject a malformed account")
	}
}

func TestProtectLeavesTheOwnerInControl(t *testing.T) {
	file := filepath.Join(t.TempDir(), "settings.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Protect(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("y"), 0o644); err != nil {
		t.Errorf("the owner lost access to a protected file: %v", err)
	}
	if EveryoneWritable(file) {
		t.Error("a protected file is writable by Everyone")
	}
}

func TestProtectWorksOnDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := Protect(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "child.txt"), []byte("x"), 0o644); err != nil {
		t.Errorf("the owner cannot write inside a protected directory: %v", err)
	}
}
