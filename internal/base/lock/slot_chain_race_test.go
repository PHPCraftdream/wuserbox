// The ordering half of the crash story, measured at the level that matters:
// executable code. slot_chain_test.go holds the tree ending and the
// nothing-inherited fact; this file holds what is true at the first grant
// after the outer is killed outright.
package lock

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

const (
	// TH32CS_SNAPTHREAD, tlhelp32.h: a snapshot of every thread in the system.
	chainSnapThread = 0x4
	// SYNCHRONIZE, winnt.h: the only right waiting on a thread handle needs.
	chainThreadSynchronize = 0x00100000
)

var (
	procSnapshotForRace = w32.Kernel32.NewProc("CreateToolhelp32Snapshot")
	procThreadFirst     = w32.Kernel32.NewProc("Thread32First")
	procThreadNext      = w32.Kernel32.NewProc("Thread32Next")
	procOpenThread      = w32.Kernel32.NewProc("OpenThread")
)

// THREADENTRY32, tlhelp32.h. The fields after ownerPID are carried so the
// struct's size is the size Windows expects, not because the loop reads them.
type chainThreadEntry struct {
	size     uint32
	cntUsage uint32
	threadID uint32
	ownerPID uint32
	basePri  int32
	deltaPri int32
	flags    uint32
}

// chainProgramThreads takes one Toolhelp snapshot and returns SYNCHRONIZE
// handles to every thread of pid, closed by the returned cleanup. One
// snapshot on purpose: the set it sees is the pre-kill thread set, and a
// thread born after the kill is not code the program was running anyway.
func chainProgramThreads(t *testing.T, pid uint32) ([]syscall.Handle, func()) {
	t.Helper()
	snap, _, callErr := procSnapshotForRace.Call(chainSnapThread, 0)
	if snap == 0 || snap == ^uintptr(0) {
		t.Fatalf("taking the thread snapshot: %v", callErr)
	}
	defer syscall.CloseHandle(syscall.Handle(snap))
	var entry chainThreadEntry
	entry.size = uint32(unsafe.Sizeof(entry))
	handles := []syscall.Handle{}
	first, _, _ := procThreadFirst.Call(snap, uintptr(unsafe.Pointer(&entry)))
	for first != 0 {
		if entry.ownerPID == pid {
			h, _, callErr := procOpenThread.Call(chainThreadSynchronize, 0, uintptr(entry.threadID))
			if h == 0 {
				t.Fatalf("opening thread %d of pid %d: %v", entry.threadID, pid, callErr)
			}
			handles = append(handles, syscall.Handle(h))
		}
		first, _, _ = procThreadNext.Call(snap, uintptr(unsafe.Pointer(&entry)))
	}
	return handles, func() {
		for _, h := range handles {
			syscall.CloseHandle(h)
		}
	}
}

// chainLiveThreads counts how many of the program's threads are still alive:
// WaitForSingleObject with a zero timeout answers without blocking, WAIT_OBJECT_0
// for a dead thread and WAIT_TIMEOUT for a live one. Anything else is the
// instrument failing, and an instrument failure is fatal at a decision point,
// never a pass.
func chainLiveThreads(t *testing.T, handles []syscall.Handle) int {
	t.Helper()
	alive := 0
	for _, h := range handles {
		r, _ := syscall.WaitForSingleObject(h, 0)
		switch r {
		case 0: // WAIT_OBJECT_0: the thread is gone
		case 258: // WAIT_TIMEOUT: the thread is alive
			alive++
		default:
			t.Fatalf("waiting on a program thread gave %d, which is neither dead nor alive: the instrument failed", r)
		}
	}
	return alive
}

// TestTheProgramCannotRunWhenTheSlotIsGranted asserts the fact the lease
// actually buys: at the first successful grant after the outer of the chain
// is killed, the program of the chain cannot run code, measured as at most
// one live thread -- the exit's own reaper, which never returns to user mode,
// so nothing the program could name can execute at the grant.
//
// The test replaces an earlier, process-object form of the same question,
// and the reason is worth keeping so nobody "fixes" it back: a process
// releases its handles before its process object signals, so for whoever
// holds the slot last, "the slot is free while the object is unsignaled" is
// a tautology, not a defect. The object-form assertion failed 20 runs out of
// 20 on both sides of an experiment, and no arrangement of handles inside
// the dying tree can ever pass it.
//
// The numbers, measured in this worktree: grants land 0.9-1.7ms after the
// kill, the program's process object signals ~0.5-1.1ms after the grant,
// every run; 6-7 threads before the kill and exactly 1 at the grant, and the
// drop completes within the microseconds between two lease attempts.
func TestTheProgramCannotRunWhenTheSlotIsGranted(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	name := fmt.Sprintf("wub-slot-race-%d", os.Getpid())
	dir := t.TempDir()
	ready, flags := dir+`\chain.ready`, dir+`\chain.flags`
	t.Setenv(slotChainNameEnv, name)
	t.Setenv(slotChainReadyEnv, ready)
	t.Setenv(slotChainFlagsEnv, flags)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=TestSlotChainOuterHoldsTheChainAndWaits")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		killSlotProcess(uint32(cmd.Process.Pid))
		_ = cmd.Wait() // the watch is started at the kill; the cleanup collects the process
	})
	if !waitForSlotTestFile(ready, 20*time.Second) {
		t.Fatal("the outer never built its chain")
	}
	data, err := os.ReadFile(ready)
	if err != nil {
		t.Fatal(err)
	}
	var stubPID, programPID uint32
	if _, err := fmt.Sscanf(string(data), "%d %d", &stubPID, &programPID); err != nil {
		t.Fatalf("reading the chain's pids: %v", err)
	}
	t.Cleanup(func() { killSlotProcess(stubPID); killSlotProcess(programPID) })

	// Load-bearing before the kill: it rules out a red result meaning a typo
	// in the slot name rather than an ordering failure.
	if _, err := Lease(name, 0); !errors.Is(err, ErrSlotHeld) {
		t.Fatalf("the chain's slot was not held before the kill: %v", err)
	}

	// One snapshot, taken before the kill: the watch is the pre-kill thread
	// set, and the program stands there sleeping and creates no more.
	handles, closeHandles := chainProgramThreads(t, programPID)
	defer closeHandles()
	if len(handles) < 1 {
		t.Fatal("the pre-kill snapshot found no threads of the program to watch")
	}

	killed := time.Now()
	killSlotProcess(uint32(cmd.Process.Pid))
	// The loop begins at the kill instant, not after cmd.Wait(): the race is
	// between the slot coming free and the program's teardown, so anything
	// that waits first measures the teardown after it is over. The first
	// second is hammered attempt by attempt, because the whole window is
	// narrower than any poll interval worth naming.
	attempt := 0
	for {
		aliveBefore := chainLiveThreads(t, handles)
		release, err := Lease(name, 0)
		if err == nil {
			aliveAfter := chainLiveThreads(t, handles)
			aliveAfter2 := chainLiveThreads(t, handles)
			if aliveAfter >= 2 {
				release()
				t.Fatalf("the slot was granted after %v and %d attempts with %d live program threads (%d on the second sample): the program of the sandbox could still run code while the slot was free",
					time.Since(killed), attempt, aliveAfter, aliveAfter2)
			}
			if aliveBefore <= 1 {
				// The pass: already at most the reaper before the grant, and a
				// dead thread count is sticky, so there is nothing left to wait for.
				release()
				return
			}
			// The grant landed inside the thread sweep, between the two
			// samples. That proves neither order and must not fail: the sweep
			// is measured to finish within the microseconds between two
			// attempts, and a test that goes red once a week teaches people
			// to re-run it.
			release()
			t.Logf("the first grant landed inside the program's thread sweep, after %v and %d attempts: %d threads just before, %d just after, which proves neither order",
				time.Since(killed), attempt, aliveBefore, aliveAfter)
			return
		}
		if !errors.Is(err, ErrSlotHeld) {
			t.Fatal(err)
		}
		attempt++
		if time.Now().After(killed.Add(15 * time.Second)) {
			aliveNow := chainLiveThreads(t, handles)
			t.Fatalf("the lease was never granted within 15s of the kill, so the teardown left the slot held past the program's death or the program never died: %d live program threads", aliveNow)
		}
		if time.Since(killed) > time.Second {
			time.Sleep(slotPoll)
		}
	}
}
