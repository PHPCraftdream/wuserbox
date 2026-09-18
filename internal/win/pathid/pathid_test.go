package pathid

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWithinFileRootRejectsAnExternalHardLinkByFileIdentity(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	file := filepath.Join(root, "settings.json")
	link := filepath.Join(outside, "settings.json")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, link); err != nil {
		t.Skipf("hard links unavailable on this volume: %v", err)
	}

	if inside, err := Within(file, file); err != nil || !inside {
		t.Fatalf("the file root did not contain its own entry: inside=%v err=%v", inside, err)
	}
	if inside, err := Within(file, link); err != nil || inside {
		t.Fatalf("the file root accepted an external hard-link name: inside=%v err=%v", inside, err)
	}
}
