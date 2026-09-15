package facts

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
)

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
