package profile

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// useProfile points the config package and paths.Home at fresh temporary
// directories and writes a rules file whose profile section is entries, the
// way a hand-edited or pre-filled rules file would.
func useProfile(t *testing.T, entries []string) (home, dest string) {
	t.Helper()
	home = t.TempDir()
	dest = filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	if err := (&config.Config{Profile: config.Entries(entries)}).Save(); err != nil {
		t.Fatal(err)
	}
	return home, dest
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// lastCopied remembers what the previous Copy reported for a destination.
// Threading that list into the next call is the caller's job in a real run --
// it is how Copy knows what to clear, and it deliberately lives outside the
// profile, where the sandbox cannot edit it into an instruction to delete
// something else. A test that passed nil every time would be testing
// something no run does.
//
// lastPrints does the same for the fingerprints, kept by the caller for the
// same reason.
var lastCopied = map[string][]config.Entry{}
var lastPrints = map[string]map[string]Print{}

func fill(t *testing.T, dest string) []config.Entry {
	t.Helper()
	copied, prints, err := Copy(dest, lastCopied[dest], lastPrints[dest])
	if err != nil {
		t.Fatal(err)
	}
	lastCopied[dest] = copied
	lastPrints[dest] = prints
	return copied
}

// pathsOf is the entries' own paths, for tests that care what was copied
// rather than the entries whole.
func pathsOf(entries []config.Entry) []string {
	paths := make([]string, len(entries))
	for i, entry := range entries {
		paths[i] = entry.Path
	}
	return paths
}

func TestCopyPlacesListedEntriesAtTheSameRelativeSpot(t *testing.T) {
	home, dest := useProfile(t, []string{".claude", ".gitconfig"})
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"a":1}`)
	write(t, filepath.Join(home, ".gitconfig"), "[user]\n")

	copied := fill(t, dest)
	sort.Strings(pathsOf(copied))
	if !reflect.DeepEqual(pathsOf(copied), []string{".claude", ".gitconfig"}) {
		t.Errorf("reported %v", copied)
	}
	if got := read(t, filepath.Join(dest, ".claude", "settings.json")); got != `{"a":1}` {
		t.Errorf("the copy holds %q", got)
	}
	if got := read(t, filepath.Join(dest, ".gitconfig")); got != "[user]\n" {
		t.Errorf("the copy holds %q", got)
	}
}

func TestCopySkipsMissingEntriesWithoutError(t *testing.T) {
	home, dest := useProfile(t, []string{".claude", ".codex"})
	write(t, filepath.Join(home, ".claude", "settings.json"), "{}")

	copied := fill(t, dest)
	if !reflect.DeepEqual(pathsOf(copied), []string{".claude"}) {
		t.Errorf("reported %v, the missing entry should have been left out silently", copied)
	}
	if _, err := os.Stat(filepath.Join(dest, ".codex")); err == nil {
		t.Error("a name that does not exist on this machine was copied anyway")
	}
}

// TestCopyNeverTouchesTheSource is the guard for the one-way rule: nothing a
// caller can do with the copy - including editing it - is allowed to reach
// back into what it came from.
func TestCopyNeverTouchesTheSource(t *testing.T) {
	home, dest := useProfile(t, []string{".gitconfig"})
	write(t, filepath.Join(home, ".gitconfig"), "[user]\n\tname = real\n")

	fill(t, dest)
	write(t, filepath.Join(dest, ".gitconfig"), "[user]\n\tname = tampered\n")

	fill(t, dest)
	if got := read(t, filepath.Join(home, ".gitconfig")); got != "[user]\n\tname = real\n" {
		t.Errorf("the source changed to %q", got)
	}
}

// TestCopyReconcilesADirectoryToMatchItsSource covers the freshness rule:
// the copy still reconciles a directory's shape to its source on every call
// -- stray files the source does not have are removed, and a copy whose size
// no longer matches its source is rewritten -- while an edited file whose
// size and source both still match now keeps the edit until the source
// changes, which is the skip's stated trade.
func TestCopyReconcilesADirectoryToMatchItsSource(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"v":1}`)
	fill(t, dest)

	write(t, filepath.Join(dest, ".claude", "settings.json"), `{"v":"tampered"}`)
	write(t, filepath.Join(dest, ".claude", "stray.txt"), "left behind by a run")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".claude", "settings.json")); got != `{"v":1}` {
		t.Errorf("the edited copy was kept: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dest, ".claude", "stray.txt")); !os.IsNotExist(err) {
		t.Error("a file the source does not have survived a copy")
	}
}

// TestCopyDropsEntriesRemovedFromTheList covers pruning: editing an entry
// out of the rules file must also remove what an earlier copy left behind,
// or dest would go on holding something the list no longer names.
func TestCopyDropsEntriesRemovedFromTheList(t *testing.T) {
	home := t.TempDir()
	dest := filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	write(t, filepath.Join(home, ".claude", "settings.json"), "{}")
	write(t, filepath.Join(home, ".gitconfig"), "[user]\n")

	if err := (&config.Config{Profile: config.Entries([]string{".claude", ".gitconfig"})}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)
	if err := (&config.Config{Profile: config.Entries([]string{".gitconfig"})}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)
	if _, err := os.Stat(filepath.Join(dest, ".claude")); !os.IsNotExist(err) {
		t.Error(".claude was dropped from the list but its copy is still there")
	}
	if _, err := os.Stat(filepath.Join(dest, ".gitconfig")); err != nil {
		t.Error(".gitconfig is still listed and should still be there")
	}
}

// TestCopyKeepsSiblingsUnderAScharedTopLevelDirectory covers two default
// entries that share a top segment, such as the LOCALAPPDATA and APPDATA
// entries both living under AppData: dropping one must not disturb the
// other, so pruning has to walk the shared prefix rather than clearing it
// whole.
func TestCopyKeepsSiblingsUnderASharedTopLevelDirectory(t *testing.T) {
	home := t.TempDir()
	dest := filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	write(t, filepath.Join(home, "AppData", "Local", "one", "f"), "one")
	write(t, filepath.Join(home, "AppData", "Roaming", "two", "f"), "two")

	both := []string{"AppData/Local/one", "AppData/Roaming/two"}
	if err := (&config.Config{Profile: config.Entries(both)}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)

	if err := (&config.Config{Profile: config.Entries([]string{"AppData/Roaming/two"})}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)
	if _, err := os.Stat(filepath.Join(dest, "AppData", "Local", "one")); !os.IsNotExist(err) {
		t.Error("the dropped sibling is still there")
	}
	if got := read(t, filepath.Join(dest, "AppData", "Roaming", "two", "f")); got != "two" {
		t.Errorf("the remaining sibling was disturbed: %q", got)
	}
}

// TestCopyRefusesADestinationItWasNotGiven guards the sharp edge: filling a
// profile starts by clearing it of what the list no longer names, so a
// mistaken argument is not a copy into the wrong place but a deletion of one.
func TestCopyRefusesADestinationItWasNotGiven(t *testing.T) {
	for _, dest := range []string{"", ".", "profile"} {
		if _, _, err := Copy(dest, nil, nil); err == nil {
			t.Errorf("a profile at %q was accepted, and clearing it would have run", dest)
		}
	}
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Copy(file, nil, nil); err == nil {
		t.Error("a file was accepted as a profile to fill")
	}
	missing := filepath.Join(t.TempDir(), "never-made")
	if _, _, err := Copy(missing, nil, nil); err == nil {
		t.Error("a directory that does not exist was accepted as a profile to fill")
	}
}

// TestCopyLeavesTheProfilesOwnBelongingsAlone is the guard on the rule this
// nearly got wrong, and the reason the tidier-sounding one is not used.
//
// "Clear dest of everything the list does not name" reads well until dest is
// a profile: what the list does not name there is NTUSER.DAT, the Temp
// directory and whatever the profile service built under AppData. Clearing
// those is deleting the sandbox's registry. Nothing is removed that wuserbox
// did not put there.
func TestCopyLeavesTheProfilesOwnBelongingsAlone(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "settings.json"), "{}")
	// What a thin profile actually holds, none of it ever on the list.
	write(t, filepath.Join(dest, "NTUSER.DAT"), "a hive")
	write(t, filepath.Join(dest, "Temp", "scratch.tmp"), "work in progress")
	write(t, filepath.Join(dest, "AppData", "Local", "Microsoft", "UsrClass.dat"), "classes")

	fill(t, dest)

	for _, kept := range []string{
		"NTUSER.DAT",
		filepath.Join("Temp", "scratch.tmp"),
		filepath.Join("AppData", "Local", "Microsoft", "UsrClass.dat"),
	} {
		if _, err := os.Stat(filepath.Join(dest, kept)); err != nil {
			t.Errorf("%s was deleted, and it is the sandbox's own, not ours: %v", kept, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, ".claude", "settings.json")); err != nil {
		t.Errorf("the listed entry was not copied, so this test proves nothing: %v", err)
	}
}

// A recorded name is read back from disk and turned into something to delete,
// so it has to be refused where it does not land inside the profile. The list
// is kept where a sandbox cannot write it, which is the first defense; this
// is what stands behind that one.
func TestCopyRefusesARecordedNameThatClimbsOutOfTheProfile(t *testing.T) {
	_, dest := useProfile(t, []string{".claude"})
	outside := filepath.Join(filepath.Dir(dest), "not-the-profile")
	precious := filepath.Join(outside, "precious.txt")
	write(t, precious, "somebody else's")

	if _, _, err := Copy(dest, []config.Entry{{Path: "../not-the-profile"}}, nil); err == nil {
		t.Error("a recorded name pointing outside the profile was acted on")
	}
	if _, err := os.Stat(precious); err != nil {
		t.Errorf("it deleted something outside the profile: %v", err)
	}
}

// junctionTo makes a real directory junction, the kind a sandbox can make in
// its own profile without any privilege at all. Skips where the machine will
// not make one, rather than passing quietly.
func junctionTo(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a junction: %v %s", err, out)
	}
}

// TestCopyCannotBeWalkedOutOfTheProfileThroughAJunction is the regression
// guard for the worst thing in this file's history, and the reason every
// write and delete below goes through an os.Root.
//
// The sandbox owns its own profile. It needs no privilege to replace a
// directory in it with a junction pointing anywhere -- and this code runs as
// the person who owns the machine, with their rights. Before the root, the
// next run followed that junction and did exactly what it does to a copy:
// overwrote the files it thought it was refreshing and deleted the ones it
// thought were left over. Measured, on a real junction: both.
func TestCopyCannotBeWalkedOutOfTheProfileThroughAJunction(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "keep.txt"), "from the source")

	outside := t.TempDir()
	precious := filepath.Join(outside, "precious.txt")
	write(t, precious, "do not touch")
	collide := filepath.Join(outside, "keep.txt")
	write(t, collide, "this content must survive")

	copied := fill(t, dest)

	// The sandbox swaps the copied directory for a junction to somebody
	// else's.
	link := filepath.Join(dest, ".claude")
	if err := os.RemoveAll(link); err != nil {
		t.Fatal(err)
	}
	junctionTo(t, link, outside)

	if _, _, err := Copy(dest, copied, lastPrints[dest]); err != nil {
		t.Fatalf("the run could not go on past a junction the sandbox left: %v", err)
	}

	if _, err := os.Stat(precious); err != nil {
		t.Errorf("a file outside the profile was deleted through the junction: %v", err)
	}
	if got := read(t, collide); got != "this content must survive" {
		t.Errorf("a file outside the profile was overwritten through the junction: %q", got)
	}
	// And the sandbox does not get to pin the name either: the link is
	// replaced with the real copy, which is what the run was for.
	if got := read(t, filepath.Join(dest, ".claude", "keep.txt")); got != "from the source" {
		t.Errorf("the entry was not copied over the junction: %q", got)
	}
}

// And the link itself is still wuserbox's to remove: refusing to follow a
// junction must not mean a sandbox can pin a name in its own profile forever
// by putting one there.
func TestCopyCanStillClearAJunctionTheSandboxLeftBehind(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "keep.txt"), "from the source")
	outside := t.TempDir()
	write(t, filepath.Join(outside, "precious.txt"), "do not touch")

	copied := fill(t, dest)
	link := filepath.Join(dest, ".claude")
	if err := os.RemoveAll(link); err != nil {
		t.Fatal(err)
	}
	junctionTo(t, link, outside)

	// Taken off the list, so the next run has to clear it.
	if err := (&config.Config{Profile: config.Entries([]string{})}).Save(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Copy(dest, copied, lastPrints[dest]); err != nil {
		t.Fatalf("clearing a junction the sandbox left behind failed: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("the junction is still in the profile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "precious.txt")); err != nil {
		t.Errorf("clearing the junction reached what it pointed at: %v", err)
	}
}

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
	copied, prints, err := copyEntries(home, root, []config.Entry{{Path: "big"}}, 50, nil)
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
