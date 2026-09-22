package profile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

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
	_, err = mirror(filepath.Join(home, "big"), "big", "", root, info, &left, newWalk(config.Entry{Path: "big"}), map[string]Print{}, map[string]Print{})
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

// TestACopyPastItsBudgetRefusesWhenTheSourceGrowsAfterItWasMeasured is the
// stale measurement the logical ceiling is built on. The walk Stats a source,
// the budget is debited for what that Stat said, and only then is the file
// opened for copying -- and between those two readings the file is the
// volume's, not the run's: an ordinary program saving its own settings makes
// the source grow without anything about the run being unusual. A copy that
// trusted the walk's measure all the way to the bytes would carry past the
// budget on exactly the pass that reported success, so the copy itself has
// to hold the opened file against what was declared, and refuse rather than
// carry what was never declared.
func TestACopyPastItsBudgetRefusesWhenTheSourceGrowsAfterItWasMeasured(t *testing.T) {
	home, dest := useProfile(t, []string{"big"})
	write(t, filepath.Join(home, "big", "one.txt"), strings.Repeat("x", 40))

	previous := openSource
	openSource = func(name string) (*os.File, error) {
		// The walk measured this file at forty bytes and the budget was
		// debited forty; the volume, not this test, decides what the file
		// holds by the time the copy opens it. Standing inside the seam the
		// copy reads through, the file grows to eighty before the open goes
		// through -- the same move a writer to the source makes between the
		// walk's Stat and the copy, and the budget stays at forty.
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			if _, werr := f.WriteString(strings.Repeat("y", 40)); werr != nil {
				_ = f.Close()
				return nil, werr
			}
			if cerr := f.Close(); cerr != nil {
				return nil, cerr
			}
			return previous(name)
		}
		return nil, err
	}
	defer func() { openSource = previous }()

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	// The budget equals the measured size exactly: the logical check has
	// forty to spend and spends it, so any refusal has to come from the
	// copy itself rather than from the counting.
	copied, prints, err := copyEntries(home, root, []config.Entry{{Path: "big"}}, nil, 40, nil)
	_ = root.Close()
	if err == nil {
		t.Fatal("a copy whose source grew past its budget was allowed to finish")
	}
	if !strings.Contains(err.Error(), "one.txt") {
		t.Errorf("the refusal does not name the file that grew: %v", err)
	}
	if strings.Contains(err.Error(), "MB into the sandbox's profile") {
		t.Errorf("the refusal is the counting's, which had exactly enough for this file, not the copy's: %v", err)
	}
	// A stopped copy stays on the list to clear, the rule
	// TestAStoppedCopyIsStillOnTheListToClear pins, whatever stopped it.
	if len(copied) != 1 || copied[0].Path != "big" {
		t.Fatalf("the stopped entry came back as %v, and the caller has nothing to clear", copied)
	}
	// No print for a copy that never happened: a fingerprint here would
	// vouch for bytes the run refused.
	if len(prints) != 0 {
		t.Errorf("a refused copy left %d fingerprints behind, want none", len(prints))
	}
	// The refusal came before the destination was ever opened, so nothing
	// was written past the limit, or at all.
	if _, err := os.Stat(filepath.Join(dest, "big", "one.txt")); !os.IsNotExist(err) {
		t.Errorf("the destination holds a copy after the refusal: %v", err)
	}
}

// TestTheBoundedCopyWritesNotOneBytePastItsLimit is the bound under the
// refusal above, on its own: whatever the source offers and however it
// offers it, the bytes that reach the destination never go past the limit,
// and a source that stops short of it or lands exactly on it copies whole.
// The plain strings.Reader case is the source that offers everything at
// once, where the refusal lands before a single byte is written; the
// one-byte reader stands in for a source that dribbles, where the limit is
// filled exactly and the refusal arrives with the next byte -- the two
// shapes the write-nothing-past rule can be caught holding in.
func TestTheBoundedCopyWritesNotOneBytePastItsLimit(t *testing.T) {
	var out bytes.Buffer

	// More offered at once than the limit allows: refusal, and the
	// destination holds nothing, not one byte of the oversized chunk.
	n, err := copyBounded(&out, strings.NewReader(strings.Repeat("z", 60)), 40)
	if err == nil {
		t.Fatal("a copy with more to give than its budget was allowed to finish")
	}
	if n != 0 || out.Len() != 0 {
		t.Errorf("the copy moved %d bytes and the destination holds %d, want nothing written of a chunk the limit refused", n, out.Len())
	}

	// More offered a byte at a time: the limit fills exactly, and the byte
	// past it is refused without being written.
	out.Reset()
	n, err = copyBounded(&out, iotest.OneByteReader(strings.NewReader(strings.Repeat("z", 60))), 40)
	if err == nil {
		t.Fatal("a copy past its budget was allowed to finish")
	}
	if n != 40 || out.Len() != 40 {
		t.Errorf("the copy moved %d bytes and the destination holds %d, want exactly the limit's 40 and nothing past it", n, out.Len())
	}

	// Fewer than the limit: an ordinary short copy, and it succeeds whole.
	out.Reset()
	n, err = copyBounded(&out, strings.NewReader("short"), 40)
	if err != nil {
		t.Fatalf("a copy under its budget was refused: %v", err)
	}
	if n != 5 || out.String() != "short" {
		t.Errorf("the copy moved %d bytes and the destination holds %q, want all five", n, out.String())
	}

	// Exactly the limit: the boundary is inclusive, and the copy succeeds.
	out.Reset()
	n, err = copyBounded(&out, strings.NewReader(strings.Repeat("z", 40)), 40)
	if err != nil {
		t.Fatalf("a copy exactly its budget was refused: %v", err)
	}
	if n != 40 || out.Len() != 40 {
		t.Errorf("the copy moved %d bytes and the destination holds %d, want 40 of each", n, out.Len())
	}

	// No limit and nothing to copy: zero-length files are ordinary, and
	// copying nothing is succeeding.
	out.Reset()
	n, err = copyBounded(&out, strings.NewReader(""), 0)
	if err != nil {
		t.Fatalf("an empty copy at a zero budget was refused: %v", err)
	}
	if n != 0 || out.Len() != 0 {
		t.Errorf("an empty copy moved %d bytes and the destination holds %d, want nothing at all", n, out.Len())
	}
}
