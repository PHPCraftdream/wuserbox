package grant

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPruneResolvesEachKeyOnce is the close test for working out per pass
// what does not change per object: the root key once per call, each keep key
// once per held path, and the key of an object once per entry the walk
// reaches. Working a key out opens the path and asks Windows for the
// directory entry it names, and the walk used to pay that three times for
// every entry, the root included.
func TestPruneResolvesEachKeyOnce(t *testing.T) {
	const account = "S-1-5-21-1111111111-2222222222-3333333333-606061"
	root := t.TempDir()
	for _, dir := range []string{"one", "two"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, file := range []string{"a.txt", "b.txt", "c.txt"} {
			if err := os.WriteFile(filepath.Join(root, dir, file), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The walk reaches the root, both directories and the three files of
	// "one"; "two" is held, so the walk stops at it rather than entering.
	const visited = 6

	rootKeys := rootKeyCalls.Load()
	keepKeys := keepKeyCalls.Load()
	leafKeys := leafKeyCalls.Load()

	if err := Prune(account, root, []string{filepath.Join(root, "two")}); err != nil {
		t.Fatal(err)
	}

	if got := rootKeyCalls.Load() - rootKeys; got != 1 {
		t.Errorf("one Prune resolved the root key %d times, want once", got)
	}
	if got := keepKeyCalls.Load() - keepKeys; got != 1 {
		t.Errorf("one held path was resolved %d times, want once", got)
	}
	if got := leafKeyCalls.Load() - leafKeys; got != visited {
		t.Errorf("a walk reaching %d entries resolved %d object keys, want one per entry", visited, got)
	}
}
