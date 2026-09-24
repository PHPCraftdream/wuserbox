package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCopyAndPlanRejectNonMissingSourceStatErrors uses a NUL in a source
// name: both supported platforms reject it with an error other than not-exist.
func TestCopyAndPlanRejectNonMissingSourceStatErrors(t *testing.T) {
	for _, operation := range []struct {
		name string
		call func(string) error
	}{
		{
			name: "Copy",
			call: func(dest string) error {
				_, _, err := Copy(dest, nil, nil)
				return err
			},
		},
		{
			name: "Plan",
			call: func(dest string) error {
				_, _, err := Plan(dest, nil)
				return err
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			home, dest := useProfile(t, []string{"bad\x00source"})
			_, statErr := os.Stat(filepath.Join(home, "bad\x00source"))
			if statErr == nil || os.IsNotExist(statErr) {
				t.Fatalf("fixture did not produce a non-missing Stat error: %v", statErr)
			}

			err := operation.call(dest)
			if err == nil {
				t.Fatal("source Stat error was treated as a missing source")
			}
			if !strings.Contains(err.Error(), "bad\x00source") {
				t.Errorf("error did not identify the source: %v", err)
			}
		})
	}
}

func TestCopyStillRetainsGenuinelyMissingSources(t *testing.T) {
	home, dest := useProfile(t, []string{"agent/auth.json"})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)
	previously := fill(t, dest)
	if err := os.Remove(filepath.Join(home, "agent", "auth.json")); err != nil {
		t.Fatal(err)
	}

	copied, _, err := Copy(dest, previously, lastPrints[dest])
	if err != nil {
		t.Fatalf("a genuinely missing source failed: %v", err)
	}
	if len(copied) != 1 || copied[0].Path != "agent/auth.json" {
		t.Errorf("a prior copy was not retained for retry: %v", pathsOf(copied))
	}
}

func TestCopyStillOmitsNeverCopiedMissingSources(t *testing.T) {
	_, dest := useProfile(t, []string{"agent/auth.json"})
	copied, _, err := Copy(dest, nil, nil)
	if err != nil {
		t.Fatalf("a never-present source failed: %v", err)
	}
	if len(copied) != 0 {
		t.Errorf("a never-copied missing source was recorded: %v", pathsOf(copied))
	}
}
