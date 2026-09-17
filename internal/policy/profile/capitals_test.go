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

// fileSystemJoins answers whether this volume treats two names as one file,
// by writing through the first and reading through the second in a directory
// of its own. It is asked rather than assumed because the answer belongs to
// the volume and not to Windows: NTFS builds its uppercase table when the
// volume is formatted, from the Unicode version in use then, so two machines
// can and do disagree. Measured, September 2026: this desk opens the two
// sigmas below onto one file and a GitHub runner's volume holds them apart,
// which is what turned a test written against one volume red on the other.
func fileSystemJoins(t *testing.T, first, second string) bool {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, first), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, second))
	return err == nil && string(data) == "one"
}

// TestTheFoldNeverHoldsApartWhatTheFileSystemJoins is the invariant behind
// foldedName, asked of the volume the test is running on rather than of a
// table written down once.
//
// The two directions of a wrong fold are not equivalent, and that asymmetry
// is the design of the present list. A fold that holds apart two names the file system
// joins is what deletes: the copy lands in the entry already there, that
// entry keeps the spelling it had, the present list misses it, and the file
// the run just wrote goes as a stray. A fold that joins two names the file
// system holds apart only spares something that was not this run's to take
// -- here, on the present list and the reserved tables, the only places a
// fold is still trusted. So this pins one direction and deliberately not the other -- foldedName
// joins U+0131 with I where NTFS does not, and that is allowed.
//
// What this cannot do is promise it found anything. Which pairs a volume
// joins is the volume's business, so on a machine whose table joins nothing
// the fold gets wrong, every case below is vacuous and the test passes
// having proved nothing. It says so in its log rather than reading as
// evidence it is not.
func TestTheFoldNeverHoldsApartWhatTheFileSystemJoins(t *testing.T) {
	pairs := [][2]string{
		{"\u03a3.json", "\u03c2.json"}, // capital sigma, final sigma
		{"\u03a3.json", "\u03c3.json"}, // capital sigma, small sigma
		{"k.json", "\u212a.json"},      // k, the Kelvin sign
		{"i.json", "\u0131.json"},      // i, dotless i
		{"i.json", "\u0130.json"},      // i, capital I with dot above
		{"ss.json", "\u00df.json"},     // ss, eszett
		{"a.json", "A.json"},           // the control: every volume joins these
	}
	joined := 0
	for _, pair := range pairs {
		if !fileSystemJoins(t, pair[0], pair[1]) {
			t.Logf("%q and %q are two files on this volume; the fold may join them or not", pair[0], pair[1])
			continue
		}
		joined++
		if foldedName(pair[0]) != foldedName(pair[1]) {
			t.Errorf("this volume opens %q and %q onto one file and the fold holds them apart, so a "+
				"copy made through one spelling is taken as a stray under the other",
				pair[0], pair[1])
			continue
		}
		t.Logf("%q and %q are one file on this volume, and the fold agrees", pair[0], pair[1])
	}
	// One pair is the ASCII control, which every volume joins; what is left
	// is what this run actually got to check.
	if joined-1 < 2 {
		t.Logf("this volume joined %d of the %d pairs past the ASCII control, so most of this test "+
			"proved nothing here -- which pairs are one name is the volume's answer, not the code's",
			joined-1, len(pairs)-1)
	}
}

// TestCopyKeepsAFileTheDestinationHoldsUnderAFinalSigma is the file shape of
// the present-list defect, one alphabet over, run end to end. Where the
// volume opens \u03a3.json and \u03c2.json onto one file, a present list folded with
// strings.ToLower -- which maps the capital sigma to the small one and
// leaves the final sigma alone -- reads the destination's own entry as a
// stranger and takes the file the run just wrote. The name escapes keep this
// file ASCII; the runes are 0x3A3 and 0x3C2.
//
// What is asserted depends on what the volume does, because the defect
// itself does. That the copy is there with the source's contents is true
// either way and is asserted either way. That the destination holds nothing
// else is only meaningful where the volume joins the two spellings: where it
// does not, the stale file is a second file the sandbox owns, and sparing it
// is the fold erring in the direction that costs nothing.
func TestCopyKeepsAFileTheDestinationHoldsUnderAFinalSigma(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "\u03a3.json"), `{"token":"real"}`)
	write(t, filepath.Join(dest, ".claude", "\u03c2.json"), `{"token":"stale"}`)

	fill(t, dest)

	if got := read(t, filepath.Join(dest, ".claude", "\u03a3.json")); got != `{"token":"real"}` {
		t.Errorf("the file the run copied holds %q, not what the source holds", got)
	}
	held := namesOf(t, filepath.Join(dest, ".claude"))
	if !fileSystemJoins(t, "\u03a3.json", "\u03c2.json") {
		t.Logf("this volume holds the two sigmas apart, so the defect this test is written for "+
			"cannot arise here, and the run leaves both files standing: %v", held)
		return
	}
	if len(held) != 1 {
		t.Fatalf("the file just copied did not survive its own run: %s holds %v",
			filepath.Join(dest, ".claude"), held)
	}
}
