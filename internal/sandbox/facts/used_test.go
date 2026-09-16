package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// useTestStateDir points LOCALAPPDATA at a directory that outlives the test.
// The record tests are the first in this package to make ktav load its
// native library, and ktav extracts that library under UserCacheDir -- which
// on Windows is LOCALAPPDATA. A library loaded from inside a t.TempDir
// cannot be unlinked while the process holds it open, and the test would
// fail in its own cleanup rather than in anything it is here to measure. A
// stable directory also lets the one download serve every later run instead
// of fetching the library again each time. The names these tests record
// under are unique to them, so nothing from an earlier run is ever read.
// The directory it makes, it makes the way MarkUsed does, so a test that
// writes a record by hand does not depend on another test having run first.
func useTestStateDir(t *testing.T) {
	t.Helper()
	dir := filepath.Join(os.TempDir(), "wub-facts-test-state")
	if err := os.MkdirAll(filepath.Join(dir, "wuserbox", "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCALAPPDATA", dir)
}

func TestAMarkedSandboxRemembersWhenItWasMadeAndLastUsed(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const name = "wub-marked-00000000"

	if err := MarkUsed(name); err != nil {
		t.Fatal(err)
	}
	first, err := Times(name)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Fatal("a sandbox just marked reads back as never used")
	}
	if first.Made.IsZero() {
		t.Error("the moment it was made was not recorded")
	}

	// Far enough apart that the two are told apart on a filesystem keeping
	// whole seconds, and the marking is still the cheap operation the run
	// path can afford.
	time.Sleep(1100 * time.Millisecond)
	if err := MarkUsed(name); err != nil {
		t.Fatal(err)
	}
	second, err := Times(name)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Used.After(first.Used) {
		t.Errorf("using it again did not move the moment: %s then %s", first.Used, second.Used)
	}
	if !second.Made.Equal(first.Made) {
		t.Errorf("using it again moved when it was made: %s then %s", first.Made, second.Made)
	}
}

// A sandbox from a version that kept no marker has no moments to read, and
// the listing this feeds has to be able to say exactly that rather than be
// handed a zero time it would print as 1601 or as an error.
func TestASandboxWithNoMarkerHasNoMomentsRatherThanWrongOnes(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	life, err := Times("wub-never-marked-00000000")
	if err != nil {
		t.Fatal(err)
	}
	if life != nil {
		t.Errorf("an unmarked sandbox answered with %+v", *life)
	}
}

// Both files sit beside the temp directory, not in it, because the temp
// directory is the one thing a sandbox is given outright. Inside it, a
// sandbox could backdate its own last use, understate its own size, or
// delete the record of either.
func TestWhatIsRecordedIsNotInsideWhatTheSandboxIsGiven(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const name = "wub-marked-00000000"
	temp := filepath.Join(paths.StateDir(), "tmp", name) + string(filepath.Separator)
	for _, path := range []string{UsedMarker(name), SizeCache(name)} {
		if strings.HasPrefix(path, temp) {
			t.Errorf("%s is inside the sandbox's own temp directory %s", path, temp)
		}
	}
}

func depthPtr(n int) *int { return &n }

// TestAnOldStyleRecordOfBarePathsLoadsAsEntries pins the one compatibility
// promise the record format makes: every record written before entries
// carried limits -- one bare path per line -- reads back as bare entries,
// with no version field and no migration. A record that failed to load would
// leave a run unable to say what it had put in a sandbox's profile, and the
// clearing would never reach what landed.
func TestAnOldStyleRecordOfBarePathsLoadsAsEntries(t *testing.T) {
	useTestStateDir(t)
	const name = "wub-old-record-00000000"
	old := ".claude.json\n.codex/auth.json\nmy dir/config.toml\n"
	if err := os.WriteFile(CopiedList(name), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := Copied(name)
	if err != nil {
		t.Fatalf("the old-style record did not load: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries out of three bare lines: %v", len(entries), entries)
	}
	for i, want := range []string{".claude.json", ".codex/auth.json", "my dir/config.toml"} {
		if entries[i].Path != want {
			t.Errorf("entry %d came back as %q, want %q", i, entries[i].Path, want)
		}
		if !entries[i].Bare() {
			t.Errorf("entry %d (%s) came back carrying limits nobody wrote", i, want)
		}
	}
}

// An empty record and an empty rendering are both real states -- a --no-ai
// run writes one -- and the next run must read them as nothing was put
// there, not as a parse error.
func TestAnEmptyRecordReadsBackAsNothing(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const name = "wub-empty-record-00000000"
	if err := RecordCopied(name, nil); err != nil {
		t.Fatal(err)
	}
	entries, err := Copied(name)
	if err != nil {
		t.Fatalf("an empty record did not read back: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("an empty record came back as %v", entries)
	}
}

// The record holds the entries whole, because the clearing a later run makes
// from it has to spare what their exclusions protected -- the exclusions
// exist nowhere else once the rules file stops naming the entry.
func TestARecordCarriesTheEntriesWhole(t *testing.T) {
	useTestStateDir(t)
	const name = "wub-whole-record-00000000"
	want := []config.Entry{
		{Path: ".claude.json"},
		{Path: ".codex", Depth: depthPtr(0), Exclude: config.Masks([]string{"sessions/**"})},
	}
	if err := RecordCopied(name, want); err != nil {
		t.Fatal(err)
	}
	got, err := Copied(name)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("the record came back as %d entries, want %d", len(got), len(want))
	}
	if got[0].Path != ".claude.json" || !got[0].Bare() {
		t.Errorf("the bare entry came back as %+v", got[0])
	}
	if got[1].Path != ".codex" {
		t.Errorf("the limited entry came back with path %q", got[1].Path)
	}
	if got[1].Depth == nil || *got[1].Depth != 0 {
		t.Errorf("the limited entry came back with depth %v, want 0", got[1].Depth)
	}
	if len(got[1].Exclude) != 1 || got[1].Exclude[0].Pattern != "sessions/**" {
		t.Errorf("the exclusion did not survive the record: %v", got[1].Exclude)
	}
}
