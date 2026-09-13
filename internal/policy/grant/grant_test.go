package grant

import (
	"os"
	"path/filepath"
	"testing"
	"wuserbox/internal/win/acl"
)

const unusedAccount = "S-1-5-21-1111111111-2222222222-3333333333-654321"

func TestEntriesCoverEveryKind(t *testing.T) {
	for _, kind := range []Kind{RW, RO, File, HomeTop} {
		if len(kind.Entries()) == 0 {
			t.Errorf("kind %q produced no access entries", kind)
		}
	}
	if len(Kind("nonsense").Entries()) != 0 {
		t.Error("an unknown kind should produce no entries")
	}
}

func TestReadOnlyGrantsNoWriteBits(t *testing.T) {
	entries := RO.Entries()
	if len(entries) != 1 {
		t.Fatalf("got %d entries", len(entries))
	}
	const writeBits = 0x2 | 0x4 | 0x40 | 0x10000 // write, append, delete child, delete
	if entries[0].Access&writeBits != 0 {
		t.Errorf("read-only access mask %#x contains write bits", entries[0].Access)
	}
}

func TestHomeTopDoesNotReachSubdirectories(t *testing.T) {
	for _, e := range HomeTop.Entries() {
		if e.Inheritance&acl.InheritContainers != 0 {
			t.Errorf("entry %#v is inherited by subdirectories", e)
		}
	}
}

func TestGrantRejectsUnknownKind(t *testing.T) {
	if err := Apply(unusedAccount, t.TempDir(), "nonsense"); err == nil {
		t.Error("expected an error for an unknown kind")
	}
}

func TestGrantIsRepeatable(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := Apply(unusedAccount, dir, RW); err != nil {
			t.Fatalf("grant %d: %v", i, err)
		}
	}
	if err := Revoke(unusedAccount, dir); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Revoking again is a no-op rather than an error.
	if err := Revoke(unusedAccount, dir); err != nil {
		t.Errorf("second revoke: %v", err)
	}
}

func TestGrantReportsMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-directory")
	if err := Apply(unusedAccount, missing, RW); err == nil {
		t.Error("expected an error for a path that does not exist")
	}
}

func TestGrantOnFileKeepsItAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "single.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Apply(unusedAccount, file, File); err != nil {
		t.Fatalf("grant: %v", err)
	}
}
