// Package lock serializes the changes wuserbox makes, between its own runs and
// between the commands within one. A change is a read, a decision and a write,
// and two of those interleaved lose one of the two decisions.
package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/base/trace"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// ErrHeld says a bounded lock wait ended while another process still held the
// lock. It is separate from an I/O failure so callers can explain a busy
// setup without treating it as success.
var ErrHeld = errors.New("the lock is still held")

var (
	procLockFileEx   = w32.Kernel32.NewProc("LockFileEx")
	procUnlockFileEx = w32.Kernel32.NewProc("UnlockFileEx")
)

// Rules is the name to hold while the standing rules are read, changed and
// written back. The rules file belongs to no single sandbox, so it has a name
// of its own.
const Rules = "rules"

// Hold runs work under a name held for the caller alone, waiting for whoever
// holds it now. The name is a sandbox group, Rules for the standing rules, or
// ForPath for one directory's permissions.
//
// Reading the record, changing permissions and writing it back is one
// operation, and it has to be one operation to the rest of the machine as
// well. Two commands that each read the record, each hand over a different
// directory and each write back leave both permissions in force while the
// record remembers only the second: explain does not mention the first and
// revoke cannot find it, so a directory stays writable with nothing pointing
// at it.
//
// The lock is a file, so it works between processes, which is where the
// problem is: wuserbox is started again by the user, by a script, and by
// itself when it needs administrator rights. Nothing inside work may start
// another wuserbox for the same sandbox, because that one waits for this
// lock.
func Hold(name string, work func() error) (err error) {
	done := trace.Current().Phase("lock_wait", trace.Field{Key: "lock", Value: name})
	release, err := take(name)
	done(err)
	if err != nil {
		return err
	}
	defer release()
	err = work()
	return err
}

// HoldWait is Hold with a bounded wait. A timeout never runs work, so callers
// fail closed and may retry once the holder is gone.
func HoldWait(name string, wait time.Duration, work func() error) error {
	done := trace.Current().Phase("lock_wait", trace.Field{Key: "lock", Value: name})
	release, err := takeWait(name, exclusive, wait)
	done(err)
	if err != nil {
		return err
	}
	defer release()
	return work()
}

// How a name is held. Exclusive shuts everybody else out; shared shuts out
// only whoever wants it exclusively, which is what lets two changes deep
// inside unrelated parts of one directory run at the same time.
const (
	shared    = uintptr(0)
	exclusive = uintptr(0x2) // LOCKFILE_EXCLUSIVE_LOCK
)

// take acquires the lock file for a group, for this caller alone, and returns
// how to let it go.
func take(name string) (func(), error) { return takeAs(name, exclusive) }

const (
	lockFailImmediately = uintptr(0x1)
	lockPoll            = 50 * time.Millisecond
	holdLockViolation   = syscall.Errno(33)
)

func takeWait(name string, how uintptr, wait time.Duration) (func(), error) {
	if wait < 0 {
		wait = 0
	}
	deadline := time.Now().Add(wait)
	for {
		release, err := takeAsMode(name, how, lockFailImmediately)
		if err == nil {
			return release, nil
		}
		if !errors.Is(err, holdLockViolation) || !time.Now().Before(deadline) {
			if errors.Is(err, holdLockViolation) {
				return nil, fmt.Errorf("waiting for the lock %s: %w", name, ErrHeld)
			}
			return nil, err
		}
		time.Sleep(lockPoll)
	}
}

// takeAs is take, told how much of the name to claim.
func takeAs(name string, how uintptr) (func(), error) {
	return takeAsMode(name, how, 0)
}

func takeAsMode(name string, how, flags uintptr) (func(), error) {
	dir := filepath.Join(paths.StateDir(), "locks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("preparing the lock directory %s: %w", dir, err)
	}
	path := filepath.Join(dir, name+".lock")
	wide, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Sharing is allowed on the handle itself: the exclusion comes from the
	// byte range lock below, which waits instead of failing.
	handle, err := syscall.CreateFile(wide, syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("opening the lock %s: %w", path, err)
	}
	var overlapped syscall.Overlapped
	// Without LOCKFILE_FAIL_IMMEDIATELY this call waits for the holder rather
	// than returning, so there is nothing here that polls.
	if r, _, callErr := procLockFileEx.Call(uintptr(handle), how|flags, 0, 1, 0,
		uintptr(unsafe.Pointer(&overlapped))); r == 0 {
		_ = syscall.CloseHandle(handle)
		return nil, fmt.Errorf("waiting for the lock %s: %w", path, callErr)
	}
	// Letting go twice must do nothing the second time, and this is not
	// tidiness. A handle is a number Windows hands out again as soon as it is
	// free, so closing one twice closes whatever was given that number in
	// between — and the Go runtime is holding such numbers, one per thread it
	// parks. Closing one of those leaves a thread woken with nothing to run on,
	// which the runtime meets as a broken invariant and not as an error: it
	// crashes the process somewhere else entirely, in whatever happened to be
	// running. Seen once on a build machine, as a scheduler crash in this very
	// package, where a caller lets the lock go early and a deferred call lets
	// it go again.
	var once sync.Once
	return func() {
		once.Do(func() {
			var overlapped syscall.Overlapped
			_, _, _ = procUnlockFileEx.Call(uintptr(handle), 0, 1, 0,
				uintptr(unsafe.Pointer(&overlapped)))
			// Closing would release the lock anyway; unlocking first says so.
			_ = syscall.CloseHandle(handle)
		})
	}, nil
}
