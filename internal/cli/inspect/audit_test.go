package inspect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// TestAFindingSaysWhichAnswerItIs is the regression guard for a list that
// printed two different answers the same way.
//
// A directory open to Everyone and a directory whose permissions this account
// may not read are not the same finding, and the second one landed on the
// worst possible entries: measured on an ordinary machine, --audit named two
// other people's profiles as writable by Everyone and by Users, because their
// lists are closed to everybody and an unreadable list counts as writable.
func TestAFindingSaysWhichAnswerItIs(t *testing.T) {
	open := finding(`C:\ProgramData\something`, []string{"Everyone", "Users"})
	if !strings.Contains(open, "Everyone, Users") {
		t.Errorf("a directory open to both does not say so: %s", open)
	}
	if strings.Contains(open, "could not be read") {
		t.Errorf("a directory that was read claims it was not: %s", open)
	}

	// A deliberately dull path. The real one this was found on is
	// C:\Users\<somebody>, which carries one of the identity names inside it,
	// so a test written with that path would have caught its own path rather
	// than the answer -- as this one did, first time round.
	silent := finding(`D:\closed`, nil)
	if !strings.Contains(silent, "could not be read") {
		t.Errorf("a list that could not be read does not say so: %s", silent)
	}
	if strings.Contains(silent, "Everyone") || strings.Contains(silent, "Users") {
		t.Errorf("a list that could not be read named an identity anyway: %s", silent)
	}
}

func TestAuditKeepsFindingsWhenAChildCannotBeEnumerated(t *testing.T) {
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	partial := filepath.Join(blocked, "partial")
	if err := os.MkdirAll(partial, 0700); err != nil {
		t.Fatal(err)
	}
	wantListingErr := errors.New("controlled listing refusal")
	var findings []string
	var issues []error
	result := walkAudit([]string{root}, 2,
		func(path string) (bool, bool, error) { return path == root || path == partial, false, nil },
		func(path string) ([]os.DirEntry, error) {
			if path == blocked {
				entries, err := os.ReadDir(path)
				if err != nil {
					t.Fatal(err)
				}
				return entries, wantListingErr
			}
			return os.ReadDir(path)
		},
		func(line string) { findings = append(findings, line) },
		func(err error) { issues = append(issues, err) },
	)
	if len(findings) != 2 || !strings.Contains(findings[0], root) || !strings.Contains(findings[1], partial) {
		t.Fatalf("partial writable finding was lost: %v", findings)
	}
	if result.found != 2 || result.enumerationFailures != 1 {
		t.Errorf("got found=%d enumeration failures=%d", result.found, result.enumerationFailures)
	}
	if err := result.err(); !errors.Is(err, wantListingErr) || !strings.Contains(err.Error(), blocked) {
		t.Errorf("incomplete walk error = %v, want wrapped listing refusal", err)
	}
	if len(issues) != 1 || !errors.Is(issues[0], wantListingErr) || !strings.Contains(issues[0].Error(), blocked) {
		t.Errorf("CLI issue report lost the failed path: %v", issues)
	}
}

func TestAuditPermissionFailureIsUnknownAndIncomplete(t *testing.T) {
	root := t.TempDir()
	wantErr := errors.New("controlled permission refusal")
	var findings []string
	result := walkAudit([]string{root}, 0,
		func(string) (bool, bool, error) { return false, false, wantErr },
		func(string) ([]os.DirEntry, error) { t.Fatal("depth zero must not enumerate"); return nil, nil },
		func(line string) { findings = append(findings, line) },
		func(error) { t.Fatal("ACL unknown is not a traversal error") },
	)
	if result.found != 0 || result.permissionUnknown != 1 {
		t.Errorf("unknown permissions were treated as a writable finding: %+v", result)
	}
	if !strings.Contains(findings[0], "could not be read") || strings.Contains(findings[0], "Everyone") {
		t.Errorf("unknown permissions were mislabeled: %q", findings[0])
	}
	if err := result.err(); err != nil {
		t.Errorf("ACL unknown should preserve the previous nonfatal status, got %v", err)
	}
}

func TestFixedDrivesRetriesAndKeepsEveryReturnedRoot(t *testing.T) {
	list := []uint16{'C', ':', '\\', 0, 'D', ':', '\\', 0, 0}
	var calls int
	var firstBufferSize int
	drives, err := fixedDrivesWith(func(buf []uint16) (uint32, error) {
		calls++
		if calls == 1 {
			firstBufferSize = len(buf)
			return uint32(len(buf)), nil
		}
		if len(buf) <= firstBufferSize {
			t.Errorf("retry buffer did not grow: %d after %d", len(buf), firstBufferSize)
		}
		copy(buf, list)
		return uint32(len(list) - 1), nil
	}, func(drive string) (uint32, error) {
		return 3, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(drives) != 2 || drives[0] != "C:\\" || drives[1] != "D:\\" {
		t.Errorf("got calls=%d drives=%v", calls, drives)
	}
}

func TestFixedDrivesRejectsZeroOrFailedWinAPIResult(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query func([]uint16) (uint32, error)
	}{
		{name: "zero", query: func([]uint16) (uint32, error) { return 0, nil }},
		{name: "error", query: func([]uint16) (uint32, error) { return 0, errors.New("controlled API failure") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if drives, err := fixedDrivesWith(tc.query, func(string) (uint32, error) { return 3, nil }); err == nil || len(drives) != 0 {
				t.Errorf("got drives=%v err=%v, want an error and no roots", drives, err)
			}
		})
	}
}

func TestFixedDrivesKeepsClassifiedRootsWhenDriveTypeFails(t *testing.T) {
	list := []uint16{'C', ':', '\\', 0, 'D', ':', '\\', 0, 0}
	wantErr := errors.New("controlled drive type failure")
	drives, err := fixedDrivesWith(func(buf []uint16) (uint32, error) {
		copy(buf, list)
		return uint32(len(list) - 1), nil
	}, func(drive string) (uint32, error) {
		if drive == "D:\\" {
			return 0, wantErr
		}
		return 3, nil
	})
	if !errors.Is(err, wantErr) || len(drives) != 1 || drives[0] != "C:\\" {
		t.Errorf("got drives=%v err=%v, want the classified C root and wrapped D failure", drives, err)
	}
}

// TestAnOrdinaryDirectoryIsReadable keeps the new test from crying wolf: if
// everything counted as unreadable, the line above would be the only one
// anybody ever saw.
func TestAnOrdinaryDirectoryIsReadable(t *testing.T) {
	dir := t.TempDir()
	if acl.Unreadable(dir) {
		t.Errorf("a directory this account just made is reported as one it cannot read: %s", dir)
	}
	if acl.Unreadable(os.Getenv("SystemRoot")) {
		t.Error("the Windows directory is reported as one this account cannot read")
	}
}
