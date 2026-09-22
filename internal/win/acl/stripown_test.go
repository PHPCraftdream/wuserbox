package acl

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// TestAStripPassResolvesIdentitiesOnceForTheWholeTree is the close test for
// resolving what a pass needs once instead of per object: one pass over a
// tree of several files costs one identity resolution and one ask of the
// group for its members, whatever the size of the tree. The current user is
// the account here because a synthetic identifier names no account at all,
// and the ask is the part that never happens for one; it answers that there
// is no such alias, which is an answer all the same.
func TestAStripPassResolvesIdentitiesOnceForTheWholeTree(t *testing.T) {
	user, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	const files = 5
	for i := 0; i < files; i++ {
		path := filepath.Join(root, "file"+strconv.Itoa(i)+".txt")
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	resolutions := identityResolutions.Load()
	lookups := memberLookups.Load()

	pass, err := BeginStripOwn(IdentifierAlone(user))
	if err != nil {
		t.Fatal(err)
	}
	stripped := 0
	err = filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		stripped++
		return pass.Strip(name)
	})
	pass.End()
	if err != nil {
		t.Fatal(err)
	}
	if stripped != files {
		t.Fatalf("the pass reached %d files, want %d", stripped, files)
	}
	if got := identityResolutions.Load() - resolutions; got != 1 {
		t.Errorf("a pass over %d files resolved the identities %d times, want once", files, got)
	}
	if got := memberLookups.Load() - lookups; got != 1 {
		t.Errorf("a pass over %d files asked the group for its members %d times, want once", files, got)
	}
}

// TestASingleStripOwnResolvesOnce is the same close test for the one-object
// form: a single StripOwn pays for exactly one resolution, its own.
func TestASingleStripOwnResolvesOnce(t *testing.T) {
	file := filepath.Join(t.TempDir(), "single.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolutions := identityResolutions.Load()
	if err := StripOwn(file, IdentifierAlone(unusedAccount)); err != nil {
		t.Fatal(err)
	}
	if got := identityResolutions.Load() - resolutions; got != 1 {
		t.Errorf("one StripOwn resolved the identities %d times, want once", got)
	}
}
