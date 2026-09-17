package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// TestTheCopyStopsWhenItHasCarriedEnough is the backstop for a rules file
// nobody generated.
//
// Retiring the entries an old default wrote fixes the files wuserbox itself
// filled in. It cannot fix one somebody composed, and a profile section that
// names a directory holding a career's worth of work would copy all of it,
// into every sandbox, on every run, exactly as the old default did -- with
// nothing at all saying so. Measured once already: 72,320 files and 19,436 MB.
//
// The budget is passed in rather than the real ceiling being reached, because
// what is under test is the counting and the refusal, not this machine's
// patience with sixty-four megabytes of temporary files.
func TestTheCopyStopsWhenItHasCarriedEnough(t *testing.T) {
	home, dest := useProfile(t, []string{"big"})
	write(t, filepath.Join(home, "big", "one.txt"), strings.Repeat("x", 40))
	write(t, filepath.Join(home, "big", "two.txt"), strings.Repeat("x", 40))

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	info, err := os.Stat(filepath.Join(home, "big"))
	if err != nil {
		t.Fatal(err)
	}
	left := int64(50) // enough for the first file, not for both
	// Empty maps rather than nil: the file that finishes before the
	// refusal still gets its fingerprint recorded, and a nil map would
	// panic on the write.
	err = mirror(filepath.Join(home, "big"), "big", "", root, info, &left, newWalk(config.Entry{Path: "big"}), map[string]Print{}, map[string]Print{})
	if err == nil {
		t.Fatal("a copy past its budget was allowed to finish")
	}
	if !strings.Contains(err.Error(), "MB into the sandbox's profile") {
		t.Errorf("the refusal does not say what stopped it: %v", err)
	}
	if !strings.Contains(err.Error(), "two.txt") && !strings.Contains(err.Error(), "one.txt") {
		t.Errorf("the refusal does not name where it went over: %v", err)
	}
}

// TestAnOrdinaryCopyIsNowhereNearTheCeiling is the other half: a budget that
// refused what it should allow would be worse than none, since the whole
// point of the narrow default is that it costs nothing to carry.
func TestAnOrdinaryCopyIsNowhereNearTheCeiling(t *testing.T) {
	home, dest := useProfile(t, []string{".claude/settings.json"})
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"theme":"dark"}`)

	copied, _, err := Copy(dest, nil, nil)
	if err != nil {
		t.Fatalf("an ordinary copy was refused: %v", err)
	}
	if len(copied) != 1 {
		t.Errorf("copied %v, want the one entry named", copied)
	}
}

// TestAStoppedCopyIsStillOnTheListToClear is what a record of "what was
// copied" is actually for.
//
// It is not a receipt, it is the only thing that knows what to take back. A
// copy stopped in the middle -- by the ceiling, or by a file that could not
// be read, or by anything else -- leaves a directory with some of its files
// in it, and the name of that directory has to come back with the error or
// nothing will ever reach what landed. Recording it only on success meant the
// caller wrote down a list without it, and the half-copied directory stayed
// in the sandbox's profile for good.
func TestAStoppedCopyIsStillOnTheListToClear(t *testing.T) {
	home, dest := useProfile(t, []string{"big"})
	write(t, filepath.Join(home, "big", "one.txt"), strings.Repeat("x", 40))
	write(t, filepath.Join(home, "big", "two.txt"), strings.Repeat("x", 40))

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	// Enough for the first file, not for both.
	copied, prints, err := copyEntries(home, root, []config.Entry{{Path: "big"}}, nil, 50, nil)
	_ = root.Close()
	if err == nil {
		t.Fatal("a copy past its budget was allowed to finish")
	}
	if len(copied) != 1 || copied[0].Path != "big" {
		t.Fatalf("the stopped entry came back as %v, and the caller has nothing to clear", copied)
	}
	// The fingerprints follow the same rule as the list: the file that
	// finished is vouched for, the one the run never reached is not. A
	// print for an unfinished copy would let the next run skip a file that
	// may not be whole.
	if len(prints) != 1 {
		t.Fatalf("a stopped copy left %d fingerprints behind, want 1 for the file that finished", len(prints))
	}
	if _, ok := prints["big/one.txt"]; !ok {
		t.Errorf("the fingerprint came back as %v, want one for big/one.txt", prints)
	}

	// And the clearing reaches it, which is the point of it being on the list.
	if err := Clear(dest, copied); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "big")); err == nil {
		t.Error("what the stopped copy left behind is still in the profile")
	}
}
