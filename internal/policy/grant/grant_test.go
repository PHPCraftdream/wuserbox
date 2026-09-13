package grant

import (
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"os"
	"path/filepath"
	"testing"
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

// TestReadOnlyRefusesChangesRatherThanOmittingThem is the regression guard for
// a read-only grant that was read-only in name only: leaving the write bits
// out of a permission does nothing about a write the parent directory hands
// down, so narrowing a directory inside a handed-over one changed nothing.
func TestReadOnlyRefusesChangesRatherThanOmittingThem(t *testing.T) {
	entries := RO.Entries()
	const writeBits = 0x2 | 0x4 | 0x40 | 0x10000 // write, append, delete child, delete

	var refusesChanges, allowsReading bool
	for _, entry := range entries {
		if entry.Refuse {
			if entry.Access&writeBits != writeBits {
				t.Errorf("the refusal covers %#x, which leaves some way to change the directory", entry.Access)
			}
			refusesChanges = true
			continue
		}
		if entry.Access&writeBits != 0 {
			t.Errorf("the permission %#x contains write bits", entry.Access)
		}
		allowsReading = true
	}
	if !refusesChanges {
		t.Error("a read-only grant does not refuse anything")
	}
	if !allowsReading {
		t.Error("a read-only grant does not allow reading")
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
