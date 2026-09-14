package lock

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

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

	other := exec.Command(os.Args[0], "-test.run=TestLockHelperTakesTheLock")
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
