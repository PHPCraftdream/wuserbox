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

// TestCopyRefusesAnExternalHardLinkBeforeTruncatingIt is the regression for
// the boundary os.Root cannot provide: it pins names, while an NTFS hard link
// makes two names one writable file object.
func TestCopyRefusesAnExternalHardLinkBeforeTruncatingIt(t *testing.T) {
	home, dest := useProfile(t, []string{".gitconfig"})
	write(t, filepath.Join(home, ".gitconfig"), "source contents\n")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	write(t, outside, "outside contents\n")
	link := filepath.Join(dest, ".gitconfig")
	if out, err := exec.Command("cmd.exe", "/c", "mklink", "/H", link, outside).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}

	_, _, err := Copy(dest, nil, nil)
	if err == nil {
		t.Fatal("copy overwrote a destination hard-linked outside the profile")
	}
	if !strings.Contains(err.Error(), "hard-linked outside") {
		t.Fatalf("copy refused the link without an actionable diagnostic: %v", err)
	}
	if got := read(t, outside); got != "outside contents\n" {
		t.Fatalf("copy modified the external hard-link target: %q", got)
	}
}

// TestCopyAllowsHardLinksWhoseNamesStayInTheProfile keeps the useful case:
// deduplicated files inside one profile are safe because every name remains
// within the profile boundary.
func TestCopyAllowsHardLinksWhoseNamesStayInTheProfile(t *testing.T) {
	home, dest := useProfile(t, []string{".gitconfig"})
	write(t, filepath.Join(home, ".gitconfig"), "source contents\n")
	alias := filepath.Join(dest, "alias.txt")
	write(t, alias, "old contents\n")
	link := filepath.Join(dest, ".gitconfig")
	if out, err := exec.Command("cmd.exe", "/c", "mklink", "/H", link, alias).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}

	if _, _, err := Copy(dest, nil, nil); err != nil {
		t.Fatalf("copy refused hard links wholly inside the profile: %v", err)
	}
	if got := read(t, alias); got != "source contents\n" {
		t.Fatalf("internal hard-link alias did not receive the copy: %q", got)
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

// TestAnExclusionSparesTheDestinationsSpellingOfAName is the exclusion half
// of the mask fold, end to end: the rules exclude one spelling of a name,
// the sandbox holds a file under another the volume opens onto the same
// file, and the mirroring asks the exclusion about the destination's
// spelling. An exclusion is two statements at once -- do not bring this in,
// and this is the sandbox's to keep -- and the second is the one that fails
// when the mask folds by a different answer than the volume gives: the file
// is removed as a stray, with no error.
func TestAnExclusionSparesTheDestinationsSpellingOfAName(t *testing.T) {
	if !fileSystemJoins(t, "\u03a3.json", "\u03c2.json") {
		t.Skipf("this volume holds the two sigmas apart, so the exclusion names a different file than the destination holds and cannot spare it")
	}

	home, dest := useProfileEntries(t, []config.Entry{
		{Path: ".claude", Exclude: config.Masks([]string{"\u03a3.json"})},
	})
	write(t, filepath.Join(home, ".claude", "settings.json"), "{}")
	write(t, filepath.Join(dest, ".claude", "\u03c2.json"), "the sandbox's own")

	fill(t, dest)

	if got := read(t, filepath.Join(dest, ".claude", "\u03c2.json")); got != "the sandbox's own" {
		t.Errorf("the exclusion did not spare the file the volume holds under the other spelling: %q", got)
	}
}
