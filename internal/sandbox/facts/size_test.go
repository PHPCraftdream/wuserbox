package facts

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMeasureAddsUpEveryDirectoryItIsGiven(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const name = "wub-measured-00000000"

	profile, temp := t.TempDir(), t.TempDir()
	write(t, filepath.Join(profile, "one.txt"), 100)
	write(t, filepath.Join(profile, "deep", "two.txt"), 200)
	write(t, filepath.Join(temp, "three.txt"), 300)

	size, err := Measure(name, profile, temp)
	if err != nil {
		t.Fatal(err)
	}
	if size.Bytes != 600 {
		t.Errorf("measured %d bytes, want 600", size.Bytes)
	}
	if size.Files != 3 {
		t.Errorf("counted %d files, want 3", size.Files)
	}
	if size.Partial {
		t.Error("said the count was a floor when everything was readable")
	}

	// And the answer is there to be read back without walking anything a
	// second time, which is the whole point of writing it down.
	known, err := Known(name)
	if err != nil {
		t.Fatal(err)
	}
	if known == nil {
		t.Fatal("nothing was written down")
	}
	if known.Bytes != size.Bytes || known.Files != size.Files {
		t.Errorf("read back %+v, measured %+v", *known, *size)
	}
	if known.Taken.IsZero() {
		t.Error("the moment it was measured was not kept, so nothing can say how old the number is")
	}
}

// A sandbox that has never run has no temp directory, and one built before
// profiles existed has no profile. Neither is a broken sandbox, so neither
// is an error.
func TestADirectoryThatIsNotThereCountsAsNothing(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	size, err := Measure("wub-empty-00000000", filepath.Join(t.TempDir(), "never-made"), "")
	if err != nil {
		t.Fatal(err)
	}
	if size.Bytes != 0 || size.Files != 0 {
		t.Errorf("measured %+v for directories that do not exist", *size)
	}
	if size.Partial {
		t.Error("a directory that was never there is not a directory that could not be read")
	}
}

// Nothing measured and nothing there are different answers, and a listing
// has to be able to tell them apart: a sandbox holding gigabytes that has
// simply never been measured must not be reported as holding none.
func TestASandboxNeverMeasuredIsNotASandboxOfNoSize(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	known, err := Known("wub-unmeasured-00000000")
	if err != nil {
		t.Fatal(err)
	}
	if known != nil {
		t.Errorf("an unmeasured sandbox answered with %+v", *known)
	}
}

// A directory that refuses to open must not come out as a small, confident
// number. It makes the answer a floor and says so -- otherwise the one
// sandbox worth looking at, the one hiding something big behind a refusal,
// is the one that would look emptiest.
func TestWhatCouldNotBeReadMakesTheAnswerAFloorAndSaysSo(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	dir := t.TempDir()
	write(t, filepath.Join(dir, "one.txt"), 100)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var refused Size
	refused.add(entries[0], errors.New("access is denied"))
	if !refused.Partial {
		t.Error("an entry that could not be read did not make the answer a floor")
	}
	if refused.Files != 0 || refused.Bytes != 0 {
		t.Errorf("an entry that could not be read was counted anyway: %+v", refused)
	}

	// The root simply not being there is a different thing, and the ordinary
	// one: a sandbox that has never run has no temp directory.
	var fresh Size
	fresh.add(nil, os.ErrNotExist)
	if fresh.Partial {
		t.Error("a directory that was never there was reported as one that could not be read")
	}

	// And the floor has to survive being written down, or a later listing
	// would show the smaller number as if it were the whole of it.
	const name = "wub-floor-00000000"
	if err := writeSize(name, &refused); err != nil {
		t.Fatal(err)
	}
	known, err := Known(name)
	if err != nil {
		t.Fatal(err)
	}
	if known == nil || !known.Partial {
		t.Errorf("read back %+v, which no longer says the number is a floor", known)
	}
}

func write(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
}
