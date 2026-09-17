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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// ErrSlotHeld says the slot was still held when the wait ran out. Callers
// match it with errors.Is, to say "another run is going" rather than "the
// slot could not be opened", which is what any other failure means.
var ErrSlotHeld = errors.New("the sandbox's slot is already leased")

// TransferEnv is the environment variable passed only to the stub. It names
// a protected handoff file containing a handle duplicated into the suspended
// stub. The stub adopts that handle and holds it for its own life; the
// program is handed nothing -- the slot can come free before the chain's last
// process object signals, and what the lease actually buys at that grant is
// that the program is down to its exit's one reaper thread, which never
// returns to user mode (measured, and held by
// TestTheProgramCannotRunWhenTheSlotIsGranted). The stub, trusted and
// shielded, is the holder the guarantee rests on.
const TransferEnv = "WUSERBOX_SLOT_TRANSFER"

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

var held = struct {
	sync.Mutex
	byPath map[string]syscall.Handle
}{byPath: make(map[string]syscall.Handle)}

// Lease holds one slot of the sandbox named name for the caller alone, and
// returns how to let it go.
// A slot is one exclusive write handle: writers share nothing, so the second
// writer is refused by the kernel itself rather than queued, and the copy
// the stub adopts carries no access at all -- the exclusion lives in this
// open's share mode, not in any handle's rights. The slot is given back
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

// SlotPath returns the file whose exclusive write lease names one sandbox.
func SlotPath(name string) string {
	return filepath.Join(paths.StateDir(), name+".slot"+strconv.Itoa(slotCount))
}

// PrepareTransfer creates the protected file through which a suspended stub
// receives its duplicated lease handle. The file is readable by the sandbox's
// per-owner read group but writable only by the user who is launching it.
func PrepareTransfer(slotPath string) (string, func(), error) {
	if slotPath == "" {
		return "", nil, fmt.Errorf("the slot path is empty")
	}
	f, err := os.CreateTemp(filepath.Dir(slotPath), ".wuserbox-slot-transfer-")
	if err != nil {
		return "", nil, fmt.Errorf("creating the slot handoff: %w", err)
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("closing the slot handoff: %w", err)
	}
	if err := acl.Protect(path); err != nil {
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("protecting the slot handoff: %w", err)
	}
	var once sync.Once
	return path, func() { once.Do(func() { _ = os.Remove(path) }) }, nil
}

// PassTo duplicates the lease's write handle into a suspended target process
// and records the target-side handle value in transferPath. The target must
// not be resumed until this returns: before it can execute, either it owns a
// copy of the lease or it has not started a program at all.
//
// The duplicate carries desired access zero and is not inherited, and both
// halves are measurements rather than taste. The zero access matters because
// the source handle is opened GENERIC_READ|GENERIC_WRITE: a duplicate that
// carried the access along -- DUPLICATE_SAME_ACCESS -- let its holder set
// FILE_ATTRIBUTE_READONLY on the slot file, and once every handle closed the
// next Lease came back "Access is denied" and stayed that way, bricking
// run, --init and --rm for the sandbox until somebody cleared the bit from
// outside. Held in place by TestALeaseHandedToTheStubCarriesNoRightsOverTheSlotFile
// and TestADuplicateAloneKeepsTheSlotShutAndGivesItBackUnharmed.
//
// The duplicate is not inherited and the program is handed nothing. The
// honest reason is the measured teardown: the slot can be granted before the
// chain's last process object signals -- grants landed 0.9-1.7ms after the
// kill while the program's process object signaled another ~0.5-1.1ms later,
// every run -- and that ordering is not something a handle arrangement can
// fix, because a process releases its handles before its process object
// signals, so no arrangement of handles inside the dying tree can hold the
// slot past that. What the lease actually buys is that at the grant the
// program is down to the exit's one reaper thread, which never returns to
// user mode -- measured 8 runs out of 8, and held by
// TestTheProgramCannotRunWhenTheSlotIsGranted. An experimental inheritable
// zero-access copy -- the program itself the last holder, making that
// ordering kernel-internal rather than a race between two teardowns -- was
// measured to buy nothing here and came back out; the numbers are in
// docs/design/one-stub-for-a-sandbox.md. The stub, trusted and shielded, is
// the holder the guarantee rests on: one CloseHandle from a program holding
// a copy erases only that copy's coverage.
func PassTo(slotPath string, target syscall.Handle, transferPath string) error {
	if slotPath == "" || transferPath == "" {
		return fmt.Errorf("the slot handoff paths are empty")
	}
	held.Lock()
	source, ok := held.byPath[slotPath]
	held.Unlock()
	if !ok {
		return fmt.Errorf("the slot %s is not held by this process", slotPath)
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("getting the current process for the slot handoff: %w", err)
	}
	// Desired access zero is load-bearing -- a same-access duplicate could set
	// FILE_ATTRIBUTE_READONLY on the slot file and brick every later Lease --
	// and the duplicate is not inherited: the slot can come free before the
	// chain's last process object signals no matter how the handles are
	// arranged, because a process releases its handles before its object
	// signals, and at the grant the program is down to its exit's reaper
	// thread anyway (measured, see PassTo above).
	var duplicate syscall.Handle
	if err := syscall.DuplicateHandle(current, source, target, &duplicate, 0, false, 0); err != nil {
		return fmt.Errorf("duplicating the slot into the stub: %w", err)
	}
	if err := os.WriteFile(transferPath, []byte(strconv.FormatUint(uint64(duplicate), 10)), 0o600); err != nil {
		return fmt.Errorf("writing the slot handoff: %w", err)
	}
	return nil
}

// Adopt takes ownership of a handle value duplicated into the current
// process. The returned release function is deliberately idempotent because
// Stub also has an error path before it starts a child.
func Adopt(value string) (func(), error) {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 0, 64)
	if err == nil && (n == 0 || n == ^uint64(0) ||
		uint64(uintptr(n)) != n || uintptr(n) == ^uintptr(0)) {
		err = fmt.Errorf("invalid handle value")
	}
	if err != nil {
		return nil, fmt.Errorf("adopting the slot handle: %w", err)
	}
	handle := syscall.Handle(uintptr(n))
	var once sync.Once
	return func() { once.Do(func() { _ = syscall.CloseHandle(handle) }) }, nil
}

// takeSlot opens the slot file once, with no sharing at all. The lease handle
// is duplicated into the suspended stub before it is allowed to run.
func takeSlot(name string) (func(), error) {
	dir := paths.StateDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("preparing the state directory %s: %w", dir, err)
	}
	path := SlotPath(name)
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
	held.Lock()
	held.byPath[path] = handle
	held.Unlock()
	return func() {
		once.Do(func() {
			held.Lock()
			delete(held.byPath, path)
			held.Unlock()
			_ = syscall.CloseHandle(handle)
		})
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
