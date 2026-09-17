package profile

import (
	"os"
	"path/filepath"
	"testing"
)

// namesOf lists one directory's entries by the spelling the directory
// itself carries them under, which is what the tests here turn on: a
// case-insensitive file system answers a name asked in any capitals, and
// only ReadDir says which spelling the entry actually kept.
func namesOf(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

// TestCopyKeepsAFileTheDestinationHoldsUnderDifferentCapitals is the file
// shape of the case defect in the present list. The list is filled from the
// source's directory entries and asked about the destination's, and Windows
// opens either spelling onto the same file -- so the copy lands in the entry
// already held, which keeps the capitals it had, and the byte-exact map
// lookup then reads that entry as a stranger and deletes the file the same
// run just wrote, reporting success.
func TestCopyKeepsAFileTheDestinationHoldsUnderDifferentCapitals(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "auth.json"), `{"token":"real"}`)
	write(t, filepath.Join(dest, ".claude", "AUTH.JSON"), `{"token":"stale"}`)

	fill(t, dest)

	held := namesOf(t, filepath.Join(dest, ".claude"))
	if len(held) != 1 {
		t.Fatalf("the file just copied did not survive its own run: %s holds %v",
			filepath.Join(dest, ".claude"), held)
	}
	if got := read(t, filepath.Join(dest, ".claude", held[0])); got != `{"token":"real"}` {
		t.Errorf("the surviving entry holds %q, not what was copied into it", got)
	}
}

// TestCopyKeepsADirectoryTheDestinationHoldsUnderDifferentCapitals is the
// same defect with a directory on the line, where the cost is larger: a
// bare entry has no exclusion, include list, or depth to route the stray
// question through, so the entry mistaken for a stray reaches the plain
// RemoveAll at the bottom of removeStrayChildren and takes the whole tree
// the run just filled.
func TestCopyKeepsADirectoryTheDestinationHoldsUnderDifferentCapitals(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "skills", "commits.md"), "## Commits")
	write(t, filepath.Join(dest, ".claude", "SKILLS", "scratch.md"), "the sandbox's own")

	fill(t, dest)

	held := namesOf(t, filepath.Join(dest, ".claude"))
	if len(held) != 1 {
		t.Fatalf("the directory just filled did not survive its own run: %s holds %v",
			filepath.Join(dest, ".claude"), held)
	}
	under := namesOf(t, filepath.Join(dest, ".claude", held[0]))
	if len(under) != 1 || under[0] != "commits.md" {
		t.Fatalf("what was copied into the directory did not survive it: holds %v", under)
	}
	if got := read(t, filepath.Join(dest, ".claude", held[0], "commits.md")); got != "## Commits" {
		t.Errorf("the copied file holds %q", got)
	}
}

// TestCopySurvivesTheSourceReshapedOnlyInCapitals runs the defect against
// time: one fill, then the source renamed to differ only in capitals, then
// another. The second run copies onto the entry the first one left -- the
// print was keyed under the old spelling, so nothing is skipped -- and the
// destination's entry still says the first spelling, so the same byte-exact
// lookup fails without anybody planting a destination by hand. A case-only
// rename is how an entry's capitals are updated on NTFS; if this file
// system refuses one, the test says so rather than faking the state.
func TestCopySurvivesTheSourceReshapedOnlyInCapitals(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "note.txt"), "first")
	fill(t, dest)

	if err := os.Rename(
		filepath.Join(home, ".claude", "note.txt"),
		filepath.Join(home, ".claude", "NOTE.TXT"),
	); err != nil {
		t.Skipf("this file system does not take a case-only rename: %v", err)
	}
	if held := namesOf(t, filepath.Join(home, ".claude")); len(held) != 1 || held[0] != "NOTE.TXT" {
		t.Skipf("the rename did not leave the entry spelled NOTE.TXT: %v", held)
	}
	write(t, filepath.Join(home, ".claude", "NOTE.TXT"), "second")

	fill(t, dest)

	held := namesOf(t, filepath.Join(dest, ".claude"))
	if len(held) != 1 {
		t.Fatalf("the file the second run copied did not survive it: %s holds %v",
			filepath.Join(dest, ".claude"), held)
	}
	if got := read(t, filepath.Join(dest, ".claude", held[0])); got != "second" {
		t.Errorf("the surviving entry holds %q, not what the second run copied", got)
	}
}

// TestCopyKeepsAFileTheDestinationHoldsUnderAFinalSigma is the file shape of
// the same present-list defect, one alphabet over. NTFS opens Σ.json
// (U+03A3) and ς.json (U+03C2) onto the same file -- measured on this
// machine by writing through one spelling and reading through the other, and
// by GetFileInformationByHandle's volume serial and file index agreeing --
// but strings.ToLower maps Σ to σ and leaves ς alone, so a present list
// folded that way reads the destination's own entry as a stranger and takes
// the file the run just wrote. The name escapes keep this file ASCII; the
// runes are 0x3A3 and 0x3C2.
func TestCopyKeepsAFileTheDestinationHoldsUnderAFinalSigma(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "\u03a3.json"), `{"token":"real"}`)
	write(t, filepath.Join(dest, ".claude", "\u03c2.json"), `{"token":"stale"}`)

	fill(t, dest)

	held := namesOf(t, filepath.Join(dest, ".claude"))
	if len(held) != 1 {
		t.Fatalf("the file just copied did not survive its own run: %s holds %v",
			filepath.Join(dest, ".claude"), held)
	}
	if got := read(t, filepath.Join(dest, ".claude", held[0])); got != `{"token":"real"}` {
		t.Errorf("the surviving entry holds %q, not what was copied into it", got)
	}
}
