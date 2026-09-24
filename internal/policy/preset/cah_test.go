package preset

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultProfileCopiesCahCodeButNotItsCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	bin := filepath.Join(home, ".claude", "cah-bin", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "cah-status.js"), []byte("status"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, entry := range Profile() {
		if entry.Path != ".claude/cah-bin" {
			continue
		}
		if len(entry.Exclude) != 1 || entry.Exclude[0].Pattern != "cache/**" {
			t.Fatalf("cah default would carry its generated cache: %+v", entry)
		}
		return
	}
	t.Fatal("installed cah binary was absent from the default profile")
}
