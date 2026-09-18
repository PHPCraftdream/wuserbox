// What a grant does when a name leads somewhere else: a junction out of the
// tree, a second name for a file outside it, a link that stays within. The
// sandbox owns its own directories, so planting a link costs it no privilege
// -- which is why every one of these is measured rather than reasoned about.

package acl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

func TestAGrantDoesNotReachThroughAJunction(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writable := []ACE{{Access: AccessModify, Inheritance: InheritObjects | InheritContainers}}
	if err := Set(outside, sid.Users, writable); err != nil {
		t.Fatal(err)
	}
	if err := Set(outside, unusedAccount, writable); err != nil {
		t.Fatal(err)
	}
	beyond := filepath.Join(outside, "beyond.txt")
	if err := os.WriteFile(beyond, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, outside).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a junction: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(link) })

	// Handed to somebody else than the account already named outside, so that
	// what is found there afterwards says which direction it came from. Asking
	// only whether the outside entry survived would pass either way.
	const newcomer = "S-1-5-21-1111111111-2222222222-3333333333-543211"
	if err := Isolate(root, newcomer, writable, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if !UsersWritable(outside) {
		t.Error("granting a tree narrowed BUILTIN\\Users somewhere outside it, through a junction")
	}
	if kept, err := heldBy(outside, unusedAccount, AccessModify); err != nil || !kept {
		t.Errorf("granting a tree rewrote an entry somewhere outside it, through a junction (kept=%v, err=%v)",
			kept, err)
	}
	// The other half, and the one the comment above has always claimed: a
	// junction must not carry the new permission across either. Nothing removed
	// is only half of "does not reach through".
	if reached, err := heldBy(outside, newcomer, AccessModify); err != nil || reached {
		t.Errorf("granting a tree handed an entry to something outside it, through a junction (reached=%v, err=%v)",
			reached, err)
	}
	if reached, err := heldBy(beyond, newcomer, AccessModify); err != nil || reached {
		t.Errorf("granting a tree reached a file inside the junction's target (reached=%v, err=%v)",
			reached, err)
	}
}

// TestAnObjectWithNoListAtAllIsNarrowedToo is the regression guard for the
// widest an object gets and the one the sweep could not see.
//
// An object with no permission list is not an object with an empty one:
// Windows reads the absence as everybody holding every right. Narrowing works
// through entries, and there were none, so a directory inside a granted tree
// carrying one stayed open to every sandbox on the machine after the tree was
// handed over.

func TestAGrantRefusesAFileWithASecondNameOutside(t *testing.T) {
	granted, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "notes.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(granted, "link.txt")
	if out, err := exec.Command("cmd", "/c", "mklink", "/H", link, target).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}

	err := Isolate(granted, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil)
	if err == nil {
		t.Fatal("handed over a tree holding a second name for a file outside it")
	}
	if !strings.Contains(err.Error(), "--allow-links") {
		t.Errorf("the refusal does not say how to go ahead anyway: %v", err)
	}

	if holds(t, target, unusedAccount, "") {
		t.Error("the file outside the tree was reached despite the refusal")
	}
	if holds(t, granted, unusedAccount, "") {
		t.Error("the grant was written despite the refusal, so the tree was left changed")
	}
}

func TestAFileRootDoesNotContainAnExternalHardLinkName(t *testing.T) {
	inside, outside := t.TempDir(), t.TempDir()
	file := filepath.Join(inside, "settings.json")
	link := filepath.Join(outside, "settings.json")
	if err := os.WriteFile(file, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, link); err != nil {
		t.Skipf("hard links unavailable on this volume: %v", err)
	}

	got, err := within(file, link)
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("a file root accepted an external hard-link name")
	}
}

// TestAGrantRefusesAHardLinkAcrossFilesystemDistinctUnicodeDirectories is
// the same boundary with names that Go's Unicode fold incorrectly equates.
// The volume is the authority: if it keeps K and the Kelvin sign distinct,
// the outside hard link must still stop the grant.
func TestAGrantRefusesAHardLinkAcrossFilesystemDistinctUnicodeDirectories(t *testing.T) {
	parent := t.TempDir()
	inside := filepath.Join(parent, "K")
	outside := filepath.Join(parent, "\u212A")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Skipf("this volume does not distinguish K and Kelvin sign: %v", err)
	}
	insideInfo, err := os.Stat(inside)
	if err != nil {
		t.Fatal(err)
	}
	outsideInfo, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(insideInfo, outsideInfo) {
		t.Skip("the volume reports K and Kelvin sign as the same directory")
	}

	target := filepath.Join(outside, "notes.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(inside, "link.txt")
	if out, err := exec.Command("cmd", "/c", "mklink", "/H", link, target).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}

	err = Isolate(inside, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil)
	if err == nil {
		t.Fatal("handed over a tree whose hard link exits through a filesystem-distinct Unicode name")
	}
	if !strings.Contains(err.Error(), "--allow-links") {
		t.Errorf("the refusal does not say how to go ahead anyway: %v", err)
	}
	if holds(t, target, unusedAccount, "") {
		t.Error("the outside file was reached despite the Unicode boundary refusal")
	}
}

// TestAllowLinksHandsTheTreeOverAnyway is the other half: the refusal above is
// a default and not a wall. Somebody who knows what the links in their tree
// are -- a local git clone, a pnpm store -- says so and the grant goes ahead.
func TestAllowLinksHandsTheTreeOverAnyway(t *testing.T) {
	t.Setenv(EnvAllowLinks, "1")
	granted, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "notes.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(granted, "link.txt")
	if out, err := exec.Command("cmd", "/c", "mklink", "/H", link, target).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}

	if err := Isolate(granted, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatalf("--allow-links did not let the grant through: %v", err)
	}
	if !holds(t, granted, unusedAccount, "(M)") {
		t.Error("the grant was not written even though links were allowed")
	}
}

// TestAGrantAllowsALinkThatStaysInsideTheTree is the other side of the guard
// above, and the reason it asks where the other name is rather than how many
// there are.
//
// Refusing on any second name refused the ordinary case. Package managers
// deduplicate inside one directory -- two agents under ~/.config sharing one
// copy of a library, one agent's file history sharing a version between
// sessions -- and that is thousands of files in the very directories the
// preset hands over, none of them reaching outside. Measured on a real
// profile, after the strict form made `--init` fail on it.
func TestAGrantAllowsALinkThatStaysInsideTheTree(t *testing.T) {
	granted := t.TempDir()
	first := filepath.Join(granted, "one", "shared.txt")
	if err := os.MkdirAll(filepath.Dir(first), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(granted, "two", "shared.txt")
	if err := os.MkdirAll(filepath.Dir(second), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/H", second, first).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}

	if err := Isolate(granted, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatalf("a tree whose links all stay inside it was refused: %v", err)
	}
	if !holds(t, granted, unusedAccount, "(M)") {
		t.Error("the grant was not written")
	}
}

// TestALinkInsideATreeNamedInShortFormIsStillInside is the regression guard for
// comparing two spellings of one directory as strings.
//
// A build machine hands out its TEMP in the old eight-and-three form,
// C:\Users\RUNNER~1\..., while the names a file answers to come back spelled
// out, C:\Users\runneradmin\.... The same directory, and not the same string,
// so a tree containing a link to itself was refused as though the link led
// outside. The same would happen to anybody whose path reaches the disk
// through a substituted drive.
func TestALinkInsideATreeNamedInShortFormIsStillInside(t *testing.T) {
	long := filepath.Join(t.TempDir(), "a directory with a long name")
	if err := os.MkdirAll(filepath.Join(long, "one"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(long, "two"), 0o755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(long, "one", "shared.txt")
	if err := os.WriteFile(first, []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(long, "two", "shared.txt")
	if out, err := exec.Command("cmd", "/c", "mklink", "/H", second, first).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a hard link: %v\n%s", err, out)
	}

	short := shortForm(t, long)
	if strings.EqualFold(short, long) {
		t.Skip("this volume does not keep short names, so there is no second spelling to test")
	}

	if err := Isolate(short, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatalf("a tree named in short form was refused for containing a link to itself: %v", err)
	}
}

// shortForm asks Windows for the eight-and-three spelling of a path.
func shortForm(t *testing.T, path string) string {
	t.Helper()
	wide, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, syscall.MAX_LONG_PATH)
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetShortPathNameW")
	written, _, _ := proc.Call(uintptr(unsafe.Pointer(wide)),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if written == 0 {
		return path
	}
	return syscall.UTF16ToString(buffer[:written])
}

// TestAGrantTakesWriteFromAuthenticatedUsersToo is the regression guard for
// the identity isolation forgot.
//
// Everyone and BUILTIN\Users were narrowed; Authenticated Users was not. That
// cost nothing while a sandbox was a restricted token, whose second check
// carried neither it nor anything else outside its restricting list, so an
// entry naming it reached nobody inside. A sandbox is an account now, and an
// account carries Authenticated Users by virtue of having logged on -- so a
// directory handed to one sandbox with this entry left standing was writable
// and deletable by every other sandbox on the machine, which is the boundary
// between two sandboxes and the whole point of isolating a grant.
//
// Checked on the list rather than by running something, deliberately: the
// tests that run something run under the old mechanism, where this entry
// makes no difference and the guard would pass without the fix.
