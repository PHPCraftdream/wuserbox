package lock

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
	"github.com/PHPCraftdream/wuserbox/internal/win/quietexec"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var procGetLogicalDrives = w32.Kernel32.NewProc("GetLogicalDrives")

// freeDriveLetter returns a drive letter no volume answers to. The alias the
// test substitutes has to land on a letter the machine does not already use,
// because nothing here may touch a mapping that exists.
func freeDriveLetter(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("subst.exe"); err != nil {
		t.Skipf("subst.exe is not available: %v", err)
	}
	mask, _, callErr := procGetLogicalDrives.Call()
	if mask == 0 {
		t.Fatalf("asking which drive letters the machine knows: %v", callErr)
	}
	for letter := 'Z'; letter >= 'A'; letter-- {
		if mask&(1<<(letter-'A')) == 0 {
			return string(letter) + ":"
		}
	}
	t.Fatal("every drive letter is taken; a temporary SUBST alias has nowhere to go")
	return ""
}

// substAlias maps alias to target for the length of the test and no longer:
// the removal is a cleanup, so a test that fails partway through still takes
// its mapping off the machine on the way out.
func substAlias(t *testing.T, alias, target string) {
	t.Helper()
	out, err := quietexec.Command("subst.exe", alias, target).CombinedOutput()
	if err != nil {
		t.Fatalf("substituting %s for %s: %v: %s", alias, target, err, out)
	}
	t.Cleanup(func() {
		if out, err := quietexec.Command("subst.exe", alias, "/D").CombinedOutput(); err != nil {
			t.Errorf("removing the %s alias: %v: %s", alias, err, out)
		}
	})
	if _, err := os.Stat(alias + `\`); err != nil {
		t.Fatalf("the SUBST alias %s does not answer after being created: %v", alias, err)
	}
}

// TestASubstAliasMeetsTheRealTreeAtOneLock closes the tree-lock half of the
// drive-alias finding: a SUBST drive is one real tree under a second name,
// and two commands naming that tree differently must not take two
// independent locks and read, decide and write its access list at once.
// The alias is created here and removed here, win or lose; the mapping the
// machine came with is never touched.
func TestASubstAliasMeetsTheRealTreeAtOneLock(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	base := t.TempDir()
	tree := filepath.Join(base, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := freeDriveLetter(t)
	substAlias(t, alias, base)
	throughAlias := alias + `\tree`

	held, err := takeTree(throughAlias)
	if err != nil {
		t.Fatal(err)
	}

	// The same tree by its real name must wait at the alias's lock.
	blocked := make(chan error, 1)
	go func() {
		let, err := takeTree(tree)
		if err == nil {
			let()
		}
		blocked <- err
	}()
	select {
	case err := <-blocked:
		held()
		t.Fatalf("the same tree, named by its real path, was taken under an independent lock while the alias held it: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	// A directory beside the tree is no part of it, whichever spelling each
	// is named by, so two grants that overlap nowhere go on at once.
	sibling := make(chan error, 1)
	go func() {
		let, err := takeTree(filepath.Join(base, "beside"))
		if err == nil {
			let()
		}
		sibling <- err
	}()
	select {
	case err := <-sibling:
		if err != nil {
			held()
			t.Fatalf("a directory beside the held one: %v", err)
		}
	case <-time.After(10 * time.Second):
		held()
		t.Fatal("a directory beside the held one waited for it")
	}

	held()
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the tree never came free after the alias let it go")
	}
}

// TestMixedSpellingsKeepTakingTreesInOneOrder guards the alias fix against
// turning the collision it closes into a wait cycle. Whatever each tree is
// called by, every chain is still claimed from the volume root downwards,
// so a caller only ever waits on a directory deeper than everything it
// holds already; this interleaves the two spellings of one tree with a
// nested tree and a sibling until all of it has gone round several times,
// and asks that it all finish rather than hang.
func TestMixedSpellingsKeepTakingTreesInOneOrder(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	base := t.TempDir()
	tree := filepath.Join(base, "tree")
	nested := filepath.Join(tree, "nested")
	beside := filepath.Join(base, "beside")
	for _, directory := range []string{nested, beside} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	alias := freeDriveLetter(t)
	substAlias(t, alias, tree)
	throughAlias := alias + `\nested`

	done := make(chan error, 1)
	go func() {
		for i := 0; i < 5; i++ {
			let, err := takeTree(tree)
			if err != nil {
				done <- err
				return
			}
			let()
			let, err = takeTree(beside)
			if err != nil {
				done <- err
				return
			}
			let()
		}
		done <- nil
	}()
	go func() {
		for i := 0; i < 5; i++ {
			let, err := takeTree(throughAlias)
			if err != nil {
				done <- err
				return
			}
			let()
			let, err = takeTree(filepath.Join(base, "beside"))
			if err != nil {
				done <- err
				return
			}
			let()
		}
		done <- nil
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("mixed spellings of one tree stopped taking their locks: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("mixed spellings of one tree hung taking their locks")
		}
	}
}

// TestIdentityResolvesThroughWhatThePathSays pins the reuse: an existing
// root is identified by the same directory-entry resolution pathid applies
// everywhere else, not by a private scheme, and a root with no directory
// entry stands on its own cleaned spelling.
func TestIdentityResolvesThroughWhatThePathSays(t *testing.T) {
	existing := t.TempDir()
	canonical, err := pathid.Canonical(existing)
	if err != nil {
		t.Fatal(err)
	}
	got, err := identity(existing)
	if err != nil {
		t.Fatal(err)
	}
	if got != canonical {
		t.Fatalf("an existing root answered %q, want the directory entry %q", got, canonical)
	}
	missing := filepath.Join(t.TempDir(), "no-such-tree")
	if got, err := identity(missing); err != nil || got != filepath.Clean(missing) {
		t.Fatalf("a missing root answered %q, %v; want %q with no error", got, err, filepath.Clean(missing))
	}
}

// TestAnExistingRootThatCannotBeIdentifiedRefusesTheHold is the fail-closed
// half: an existing root whose directory entry cannot be resolved must stop
// the hold, not fall back to a lock of its own under the string it was
// called by. A path past what CreateFile answers to without the \\?\ prefix
// is such a root wherever Windows has not turned long paths on: Go's own
// Stat reaches it, the raw resolution does not.
func TestAnExistingRootThatCannotBeIdentifiedRefusesTheHold(t *testing.T) {
	long := t.TempDir()
	for len(long) <= 260 {
		long = filepath.Join(long, strings.Repeat("d", 64))
	}
	if err := os.MkdirAll(long, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(long); err != nil {
		t.Skipf("this machine cannot stat the long path at all: %v", err)
	}
	if _, err := pathid.Canonical(long); err == nil {
		t.Skip("Windows resolves long paths here, so the refusal cannot be provoked")
	}
	if _, err := identity(long); err == nil {
		t.Fatal("an existing root that cannot be identified was locked under its own string")
	}
	let, err := takeTree(long)
	if err == nil {
		let()
		t.Fatal("a tree hold was granted for a root that cannot be identified")
	}
}
