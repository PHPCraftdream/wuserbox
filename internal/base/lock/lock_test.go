package lock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/win/quietexec"
)

func TestAHoldWaitReportsAStuckHolderWithoutRunningWork(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	release, err := take("wub-bounded-wait")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	called := false
	if err := HoldWait("wub-bounded-wait", 100*time.Millisecond, func() error {
		called = true
		return nil
	}); !errors.Is(err, ErrHeld) {
		t.Fatalf("bounded wait returned %v, want ErrHeld", err)
	}
	if called {
		t.Fatal("work ran while another process still held the lock")
	}
}

func TestAHoldWaitRunsAfterTheHolderLeaves(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	release, err := take("wub-bounded-release")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		release()
	}()
	called := false
	if err := HoldWait("wub-bounded-release", time.Second, func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("work did not run after the holder released the lock")
	}
}

// TestAHeldNameShutsOutAnotherProcess is what the whole mechanism is for: the
// commands that race are separate runs of wuserbox, started by the user, by a
// script, or by wuserbox itself when it needs administrator rights.
func TestAHeldNameShutsOutAnotherProcess(t *testing.T) {
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	release, err := take("wub-two-processes")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	other := quietexec.Command(os.Args[0], "-test.run=TestLockHelperTakesTheLock")
	other.Env = append(os.Environ(), lockHelperEnv+"=1", "LOCALAPPDATA="+local)
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- other.Wait() }()

	select {
	case <-finished:
		t.Fatal("the other process took the lock while this one held it")
	case <-time.After(500 * time.Millisecond):
	}
	release()
	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("the other process failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("the other process never got the lock after it was let go")
	}
}

const lockHelperEnv = "WUSERBOX_LOCK_HELPER"

// TestLockHelperTakesTheLock is the second process of the test above. It does
// nothing when run as part of an ordinary test run.
func TestLockHelperTakesTheLock(t *testing.T) {
	if os.Getenv(lockHelperEnv) == "" {
		t.Skip("runs only as the second process of TestAHeldNameShutsOutAnotherProcess")
	}
	release, err := take("wub-two-processes")
	if err != nil {
		t.Fatal(err)
	}
	release()
}

// TestForPathIsTheSameNameForTheSameDirectory matters because two commands
// only meet at a lock if they arrive at the same name for it, and they do not
// always spell a path the same way.
func TestForPathIsTheSameNameForTheSameDirectory(t *testing.T) {
	same := []string{`C:\Projects\App`, `C:\projects\app`, `C:\Projects\App\`, `C:\Projects\.\App`}
	first := ForPath(same[0])
	for _, spelling := range same[1:] {
		if got := ForPath(spelling); got != first {
			t.Errorf("%s gives %q, want %q", spelling, got, first)
		}
	}
	if ForPath(`C:\Projects\Other`) == first {
		t.Error("two different directories share a lock")
	}
	// The name has to be usable as a file name, because that is what it is.
	for _, bad := range []string{`\`, `/`, `:`, `*`, `?`, `"`, `<`, `>`, `|`} {
		if strings.Contains(first, bad) {
			t.Errorf("the name %q holds %q, which no file name may", first, bad)
		}
	}
}

// TestContainingRunsFromTheVolumeRootDown guards the property that keeps two
// tree locks from waiting on each other: every caller claims the directories
// above its root in the same order, from the volume root downwards, so a
// caller only ever waits on something deeper than everything it already
// holds. Reverse this list and two commands can hold what the other wants.
func TestContainingRunsFromTheVolumeRootDown(t *testing.T) {
	got := containing(`C:\Users\someone\work\inner`)
	want := []string{`C:\`, `C:\Users`, `C:\Users\someone`, `C:\Users\someone\work`}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	// A volume root is contained by nothing, and asking for its parent forever
	// is how that loop would fail to end.
	if above := containing(`C:\`); len(above) != 0 {
		t.Errorf("a volume root is inside %v", above)
	}
}

// TestATreeShutsOutWhatIsInsideItButNotWhatIsBesideIt is the lock half of the
// overlapping-trees guard: a hold on a directory excludes a hold on one inside
// it, and leaves a hold on one beside it alone.
func TestATreeShutsOutWhatIsInsideItButNotWhatIsBesideIt(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const outer = `C:\wub-lock-test\outer`
	release, err := takeTree(outer)
	if err != nil {
		t.Fatal(err)
	}

	beside := make(chan error, 1)
	go func() {
		let, err := takeTree(`C:\wub-lock-test\beside`)
		if err == nil {
			let()
		}
		beside <- err
	}()
	select {
	case err := <-beside:
		if err != nil {
			t.Fatalf("a directory beside the held one: %v", err)
		}
	case <-time.After(10 * time.Second):
		release()
		t.Fatal("a directory beside the held one waited for it")
	}

	inside := make(chan error, 1)
	go func() {
		let, err := takeTree(outer + `\inner`)
		if err == nil {
			let()
		}
		inside <- err
	}()
	select {
	case err := <-inside:
		release()
		t.Fatalf("a directory inside the held one was taken while it was held: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	release()
	select {
	case err := <-inside:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a directory inside the held one never came free")
	}
}

// TestLettingGoTwiceClosesNothingTwice is the regression guard for a crash
// that never pointed at this package.
//
// Letting a lock go closed its handle, and letting it go again closed the same
// number a second time. A handle is a number Windows hands out again as soon
// as it is free, so the second close reaches whatever was given that number in
// between. The Go runtime holds such numbers — one event per thread it parks —
// and closing one of those leaves a thread woken with no processor attached,
// which the runtime meets as a broken invariant rather than as an error and
// turns into a crash somewhere else entirely. It happened on a build machine,
// in this package, as a scheduler fault with no test failing.
//
// The sentinel is the point: it takes the number the lock has just given up,
// so a second close would land on it and nothing else would say so.
func TestLettingGoTwiceClosesNothingTwice(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	release, err := take("wub-release-twice")
	if err != nil {
		t.Fatal(err)
	}
	release()

	sentinel, err := syscall.UTF16PtrFromString(filepath.Join(t.TempDir(), "sentinel"))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(sentinel, syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	release()

	// Still ours, or the second letting go took something that was not its own.
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		t.Errorf("letting the lock go twice closed a handle belonging to somebody else: %v", err)
	}
}
