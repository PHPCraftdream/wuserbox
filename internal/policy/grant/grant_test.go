package grant

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

const unusedAccount = "S-1-5-21-1111111111-2222222222-3333333333-654321"

func TestEntriesCoverEveryKind(t *testing.T) {
	for _, kind := range []Kind{RW, RO, File, HomeTop} {
		if len(kind.Entries()) == 0 {
			t.Errorf("kind %q produced no access entries", kind)
		}
	}
	if len(Kind("nonsense").Entries()) != 0 {
		t.Error("an unknown kind should produce no entries")
	}
}

// TestReadOnlyRefusesChangesRatherThanOmittingThem is the regression guard for
// a read-only grant that was read-only in name only: leaving the write bits
// out of a permission does nothing about a write the parent directory hands
// down, so narrowing a directory inside a handed-over one changed nothing.
func TestReadOnlyRefusesChangesRatherThanOmittingThem(t *testing.T) {
	entries := RO.Entries()
	const writeBits = 0x2 | 0x4 | 0x40 | 0x10000 // write, append, delete child, delete

	var refusesChanges, allowsReading bool
	for _, entry := range entries {
		if entry.Refuse {
			if entry.Access&writeBits != writeBits {
				t.Errorf("the refusal covers %#x, which leaves some way to change the directory", entry.Access)
			}
			refusesChanges = true
			continue
		}
		if entry.Access&writeBits != 0 {
			t.Errorf("the permission %#x contains write bits", entry.Access)
		}
		allowsReading = true
	}
	if !refusesChanges {
		t.Error("a read-only grant does not refuse anything")
	}
	if !allowsReading {
		t.Error("a read-only grant does not allow reading")
	}
}

func TestHomeTopDoesNotReachSubdirectories(t *testing.T) {
	for _, e := range HomeTop.Entries() {
		if e.Inheritance&acl.InheritContainers != 0 {
			t.Errorf("entry %#v is inherited by subdirectories", e)
		}
	}
}

func TestGrantRejectsUnknownKind(t *testing.T) {
	if err := Apply(unusedAccount, t.TempDir(), "nonsense"); err == nil {
		t.Error("expected an error for an unknown kind")
	}
}

// TestIsolationReachesExactlyAsFarAsThePermission pins the reach of the
// Everyone/Users replacement to the permission it accompanies. Reaching
// further narrows somebody's whole profile to read-only where it was never
// asked for; reaching less far leaves a directory whose tree carries an
// inherited write grant for either of them still open to every sandbox that
// holds it, whichever one asked for this permission.
func TestIsolationReachesExactlyAsFarAsThePermission(t *testing.T) {
	for kind, want := range map[Kind]uint32{
		RW:      acl.InheritObjects | acl.InheritContainers,
		RO:      acl.InheritObjects | acl.InheritContainers,
		File:    acl.InheritNone,
		HomeTop: acl.InheritObjects | acl.InheritNoPropagate,
	} {
		if got := kind.IsolationReach(); got != want {
			t.Errorf("%q isolates with %#x, want %#x", kind, got, want)
		}
	}
}

func TestGrantIsRepeatable(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := Apply(unusedAccount, dir, RW); err != nil {
			t.Fatalf("grant %d: %v", i, err)
		}
	}
	if err := Revoke(unusedAccount, dir); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Revoking again is a no-op rather than an error.
	if err := Revoke(unusedAccount, dir); err != nil {
		t.Errorf("second revoke: %v", err)
	}
}

func TestGrantReportsMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-directory")
	if err := Apply(unusedAccount, missing, RW); err == nil {
		t.Error("expected an error for a path that does not exist")
	}
}

func TestGrantOnFileKeepsItAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "single.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Apply(unusedAccount, file, File); err != nil {
		t.Fatalf("grant: %v", err)
	}
}

// TestApplyHoldsTheDirectoryItChanges is the regression guard for two
// sandboxes sharing one directory. Changing permissions means reading the
// whole access list, altering a copy and writing the lot back, so without a
// lock on the directory itself each of them can publish a list built before
// the other's change, and one permission disappears while its record still
// claims it. The locks around a sandbox do not help: the directory belongs to
// neither of them.
func TestApplyHoldsTheDirectoryItChanges(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	shared := t.TempDir()

	release, err := hold(lock.ForPath(shared))
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- Apply(unusedAccount, shared, RW) }()
	select {
	case err := <-finished:
		release()
		t.Fatalf("permissions were changed while the directory was held: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	release()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the change never happened after the directory was let go")
	}
}

// TestTwoAccountsKeepTheirPermissionsOnOneDirectory is the same fault seen
// from the outside: whatever order the two changes land in, both accounts have
// to end up with an entry.
func TestTwoAccountsKeepTheirPermissionsOnOneDirectory(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	shared := t.TempDir()
	const other = "S-1-5-21-1111111111-2222222222-3333333333-654322"

	var wg sync.WaitGroup
	failures := make(chan error, 2)
	for _, account := range []string{unusedAccount, other} {
		wg.Add(1)
		go func(account string) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if err := Apply(account, shared, RW); err != nil {
					failures <- err
					return
				}
			}
		}(account)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}

	listed, err := exec.Command("icacls", shared).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v", shared, err)
	}
	for _, account := range []string{unusedAccount, other} {
		if !strings.Contains(string(listed), account) {
			t.Errorf("%s lost its permission:\n%s", account, listed)
		}
	}
}

// TestAGrantWaitsForOneOnTheDirectoryAboveIt is the regression guard for two
// commands changing overlapping trees at once.
//
// Handing a directory over sweeps everything under it, so a grant on the outer
// directory and a grant on one inside it are two changes to the same objects.
// Each used to hold only its own path, so they could cross and the outer sweep
// could narrow what the inner grant had just written: no sandbox gained
// anything it was not given, but one of the two grants came out weaker than it
// was asked for, with the record still claiming the whole of it.
func TestAGrantWaitsForOneOnTheDirectoryAboveIt(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	outer := t.TempDir()
	inner := filepath.Join(outer, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}

	release, err := holdTree(outer)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- Apply(unusedAccount, inner, RW) }()
	select {
	case err := <-finished:
		release()
		t.Fatalf("a directory inside a held tree was changed while the tree was held: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	release()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the change never happened after the tree was let go")
	}
}

// TestGrantsInUnrelatedTreesDoNotWaitForEachOther is the other half of the
// guard above, and the reason the fix is not one machine-wide lock. Serializing
// every permission change would close the same hole and make each grant wait
// for every other, however far apart the two directories are.
func TestGrantsInUnrelatedTreesDoNotWaitForEachOther(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	held, other := t.TempDir(), t.TempDir()

	release, err := holdTree(held)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	finished := make(chan error, 1)
	go func() { finished <- Apply(unusedAccount, other, RW) }()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s waited for %s, which does not contain it and is not inside it", other, held)
	}
}

// hold takes a lock in the background and returns how to let it go, so a test
// can watch something wait for it.
func hold(name string) (func(), error) {
	return holding(func(work func() error) error { return lock.Hold(name, work) })
}

// holdTree is hold for a whole tree: it claims the root and every directory
// above it, the way a permission change does.
func holdTree(root string) (func(), error) {
	return holding(func(work func() error) error { return lock.HoldTree(root, work) })
}

// holding runs one of those in the background and hands back how to end it.
func holding(take func(func() error) error) (func(), error) {
	taken := make(chan error, 1)
	done := make(chan struct{})
	released := make(chan struct{})
	go func() {
		_ = take(func() error {
			taken <- nil
			<-done
			return nil
		})
		close(released)
	}()
	if err := <-taken; err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			<-released
		})
	}, nil
}

// TestPruneIsNotHeldUpByAnOpenFile answers what taking a grant back does while
// the sandbox is still running with files open.
//
// Rewriting a permission list needs the right to rewrite it, not exclusive use
// of the object, so a file somebody is holding open does not stand in the way —
// unlike deleting it, which is what makes --rm report a temp directory it could
// not remove. Every new attempt is refused straight away.
//
// What no permission change can do is reach a handle that is already open:
// Windows checks access when a file is opened and not again afterwards, so a
// process that already had it open keeps writing through that handle until it
// closes it. That is a property of Windows, not something revoking gets wrong,
// and it is why revoking a grant is not a way to stop a program already running.
func TestPruneIsNotHeldUpByAnOpenFile(t *testing.T) {
	const account = "S-1-5-21-1111111111-2222222222-3333333333-606060"
	root := t.TempDir()
	inner := filepath.Join(root, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	busy := filepath.Join(inner, "busy.log")
	if err := os.WriteFile(busy, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Apply(account, root, RW); err != nil {
		t.Fatal(err)
	}
	// Granting the inner one is what pins it, so only Prune can reach it.
	if err := Apply(account, inner, RW); err != nil {
		t.Fatal(err)
	}

	name, err := syscall.UTF16PtrFromString(busy)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	allowed := func(path string, operation access.Operation) bool {
		t.Helper()
		result, err := access.Check(access.Sandbox{Group: account}, path, operation)
		if err != nil {
			t.Fatal(err)
		}
		return result.Allowed
	}
	if !allowed(busy, access.Write) || !allowed(inner, access.Create) {
		t.Fatal("the account could not reach the file to begin with, so this proves nothing")
	}

	if err := Prune(account, root, nil); err != nil {
		t.Fatalf("a file held open stopped the grant from being taken back: %v", err)
	}

	for _, c := range []struct {
		path      string
		operation access.Operation
	}{
		{busy, access.Write},
		{busy, access.Delete},
		{inner, access.Create},
	} {
		if allowed(c.path, c.operation) {
			t.Errorf("%s on %s is still allowed after the grant was taken back",
				c.operation, filepath.Base(c.path))
		}
	}
}

// TestARefusalLeavesReadingAlone is the regression guard for a refusal that
// refused too much.
//
// Refuse used the wider of the two masks, and the wider one carries
// FILE_READ_DATA and READ_CONTROL. A restricted token's second check refuses
// the whole request the moment any bit still wanted is denied, so a file
// refused this way stopped being readable as well as unwritable. That is what
// --home-writes does to every file already in the profile root, which left the
// sandbox unable to read ~/.gitconfig or ~/.npmrc -- against the one promise
// this tool opens with.
func TestARefusalLeavesReadingAlone(t *testing.T) {
	file := filepath.Join(t.TempDir(), "settings.conf")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := acl.Set(file, unusedAccount, []acl.ACE{{Access: acl.AccessReadExecute}}); err != nil {
		t.Fatal(err)
	}
	if !acl.Reads(file, unusedAccount) {
		t.Fatal("the account cannot read the file before it is refused, so this proves nothing")
	}

	if err := Refuse(unusedAccount, file); err != nil {
		t.Fatal(err)
	}

	if !acl.Reads(file, unusedAccount) {
		t.Error("refusing a file took reading away from it as well")
	}
	// And the refusal is really there, or the check above would pass for the
	// plain reason that nothing was written at all.
	listed, err := exec.Command("icacls", file).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v", file, err)
	}
	if !strings.Contains(string(listed), "(DENY)") {
		t.Errorf("no refusal was written:\n%s", listed)
	}
}
