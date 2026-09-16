// A slot is the lease a run holds on its sandbox while it is going, and the
// reason a second run of the same sandbox cannot birth a stub into a window a
// first run's program is standing in. What that window is, and why
// arbitrating it beats narrowing it, are the subject of
// docs/design/one-stub-for-a-sandbox.md, "The recommendation: lease a slot".

package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
)

// ErrSlotHeld says the slot was still held when the wait ran out. Callers
// match it with errors.Is, to say "another run is going" rather than "the
// slot could not be opened", which is what any other failure means.
var ErrSlotHeld = errors.New("the sandbox's slot is already leased")

// slotCount is how many runs of one sandbox may go at once, and the number
// the design calls n. One is "serialize whole runs", which is the smallest
// correct step: it closes the escape, and raising it later is --init creating
// more accounts plus this one number counting higher. Nothing here may grow a
// second mechanism to raise it.
const slotCount = 1

// slotPoll bounds how late a freed slot is noticed. The kernel gives the slot
// back when its holder dies by closing the handle and never touches the file,
// so there is nothing to wait on and nothing to be notified of; noticing is a
// poll, and this says how often.
const slotPoll = 100 * time.Millisecond

// Lease holds one slot of the sandbox named name for the caller alone, and
// returns how to let it go.
//
// A slot is one exclusive file handle: opened with no sharing, so the second
// opener is refused by the kernel itself rather than queued, and given back
// by the kernel when its holder dies by any cause. That is the whole reason
// it is a file handle and not a lock file with a pid in it or a named mutex:
// there is no stale state after a crash, no timeout to tune, and no cleanup
// that has to run on anybody's death. Giving that up for convenience would
// put a dead lease between a sandbox and its next run.
//
// The file lives in the user's own state directory, which a sandboxed program
// can read through its read group but cannot write, so unlike a pipe or a
// Local\ object the name cannot be squatted from inside the sandbox. The file
// itself is left behind when the last holder lets go: an empty file that no
// handle holds is not a lease, and deleting it would race the next opener for
// nothing.
//
// wait is how long a caller whose slot is taken waits for it to come free
// before being refused with ErrSlotHeld. Waiting at all is policy rather than
// mechanism, and short on purpose: a run refused a beat after it started -- a
// script that fires two commands back to back, a wrapper's retry, a first run
// in its last second -- is an error over nothing, while a run refused after
// seconds is a real concurrent session, and its operator should hear that now
// rather than hang behind a first run that may be an agent session with hours
// left in it.
func Lease(name string, wait time.Duration) (func(), error) {
	deadline := time.Now().Add(wait)
	for {
		release, err := takeSlot(name)
		if err == nil {
			return release, nil
		}
		if !errors.Is(err, ErrSlotHeld) || !time.Now().Before(deadline) {
			return nil, err
		}
		time.Sleep(slotPoll)
	}
}

// takeSlot opens the slot file once, with no sharing at all. The exclusion is
// the sharing mode and nothing else: what the second opener gets back is the
// kernel's own refusal, and what the file contains is nothing at all.
func takeSlot(name string) (func(), error) {
	dir := paths.StateDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("preparing the state directory %s: %w", dir, err)
	}
	path := filepath.Join(dir, name+".slot"+strconv.Itoa(slotCount))
	wide, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(wide,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0, nil, // share mode zero: the whole lock
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		// Both spellings: the conflict of an exclusive open is a sharing
		// violation, and some file systems answer the same conflict with the
		// lock-violation name for it. Either way the slot is simply held,
		// which is all a waiter wants to know.
		if errors.Is(err, sharingViolation) || errors.Is(err, lockViolation) {
			return nil, fmt.Errorf("%s: %w", path, ErrSlotHeld)
		}
		return nil, fmt.Errorf("opening the slot %s: %w", path, err)
	}
	// Letting go twice must do nothing the second time, and that is not
	// tidiness: a handle is a number Windows hands out again as soon as it is
	// free, and closing a number twice closes whatever holds it now -- the
	// crash hold.go records against its own lock.
	var once sync.Once
	return func() {
		once.Do(func() { _ = syscall.CloseHandle(handle) })
	}, nil
}

// The kernel's two answers to an open that loses to somebody else's share
// mode, named here because Go's syscall package exports neither and x/sys is
// a dependency this project does not take. 32 and 33 are ERROR_SHARING_VIOLATION
// and ERROR_LOCK_VIOLATION, winerror.h.
var (
	sharingViolation = syscall.Errno(32)
	lockViolation    = syscall.Errno(33)
)
