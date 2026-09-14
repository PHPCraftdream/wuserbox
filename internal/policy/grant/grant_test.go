package grant

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/lock"
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

// TestLabelReachesExactlyAsFarAsThePermission pins the inheritance of the
// integrity label to the permission it accompanies. Reaching further marks
// somebody's whole profile as Low — the profile root may only take new files,
// and labeling the subdirectories it already has is not what was asked for.
// Reaching less far leaves the sandbox unable to write where it was just
// allowed to, because a Low token is refused anything that is not labeled Low.
func TestLabelReachesExactlyAsFarAsThePermission(t *testing.T) {
	for kind, want := range map[Kind]uint32{
		RW:      acl.InheritObjects | acl.InheritContainers,
		File:    acl.InheritNone,
		HomeTop: acl.InheritObjects | acl.InheritNoPropagate,
	} {
		if got := kind.LabelInheritance(); got != want {
			t.Errorf("%q labels with %#x, want %#x", kind, got, want)
		}
	}
	// A read-only kind hands nothing over, so it labels nothing.
	if got := RO.LabelInheritance(); got != acl.InheritNone {
		t.Errorf("%q labels with %#x, and it should label nothing", RO, got)
	}
	// Every writable kind has to name its reach; a new one that forgets would
	// be handed over and then be unwritable.
	for _, kind := range []Kind{RW, File, HomeTop} {
		if !kind.Writable() {
			t.Errorf("%q is no longer writable; this table needs revisiting", kind)
		}
	}
}

// TestAppliedSeparatesAMissingLabelFromARealFailure covers the distinction the
// whole repair path rests on: the permission going on without its label is a
// shortfall to record and come back to, while anything else is a failure.
func TestAppliedSeparatesAMissingLabelFromARealFailure(t *testing.T) {
	if !Applied(nil) {
		t.Error("no error should count as applied")
	}
	if !Applied(fmt.Errorf("labeling: %w", acl.ErrNotLabeled)) {
		t.Error("a missing label leaves the permission in force")
	}
	if Applied(errors.New("access denied")) {
		t.Error("an ordinary failure must not be read as applied")
	}
}

func TestGrantIsRepeatable(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := Apply(unusedAccount, dir, RW); !Applied(err) {
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
	if err := Apply(unusedAccount, file, File); !Applied(err) {
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
		if !Applied(err) {
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
		if !Applied(err) {
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

// hold takes a lock in the background and returns how to let it go, so a test
// can watch something wait for it.
func hold(name string) (func(), error) {
	taken := make(chan error, 1)
	done := make(chan struct{})
	released := make(chan struct{})
	go func() {
		_ = lock.Hold(name, func() error {
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
