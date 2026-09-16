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

// TestAHeldSlotShutsOutASecondLease is the lease itself: the second opener of
// a slot the first still holds is refused, and refused with the sentinel that
// says "held" rather than an error that could mean anything. A caller that
// cannot tell those apart cannot say what happened to the person who typed
// the command.
func TestAHeldSlotShutsOutASecondLease(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	name := fmt.Sprintf("wub-slot-busy-%d", os.Getpid())

	release, err := Lease(name, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	if _, err := Lease(name, 50*time.Millisecond); !errors.Is(err, ErrSlotHeld) {
		t.Fatalf("a second lease of a held slot came back as %v, and should have come back as ErrSlotHeld", err)
	}
}

// TestALeaseWaitsForASlotItsHolderLetsGo is the half that keeps a second run
// from erroring over a first that was ending anyway: a slot that comes free
// inside the wait is taken, and taken by the wait rather than by luck.
func TestALeaseWaitsForASlotItsHolderLetsGo(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	name := fmt.Sprintf("wub-slot-freed-%d", os.Getpid())

	release, err := Lease(name, 0)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		release()
	}()

	before := time.Now()
	second, err := Lease(name, 5*time.Second)
	if err != nil {
		t.Fatalf("a slot let go inside the wait was never taken: %v", err)
	}
	defer second()
	if waited := time.Since(before); waited < 200*time.Millisecond {
		t.Errorf("the lease came back after %s, which is sooner than its holder let go", waited)
	}
}

// TestASlotFreesWhenItsHolderDies is the property the whole design leans on:
// the kernel, and not any cleanup of this program's, gives the slot back, so
// a crash leaves no stale state behind, nothing to time out and nothing to
// repair. The child below takes the slot and dies holding it -- os.Exit runs
// no defers, which is exactly "by any cause".
func TestASlotFreesWhenItsHolderDies(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	name := fmt.Sprintf("wub-slot-dies-%d", os.Getpid())

	other := exec.Command(os.Args[0], "-test.run=TestSlotHelperTakesTheSlotAndDies")
	other.Env = append(os.Environ(), slotHelperEnv+"="+name)
	if err := other.Run(); err != nil {
		t.Fatalf("the child that dies holding the slot failed: %v", err)
	}

	release, err := Lease(name, 5*time.Second)
	if err != nil {
		t.Fatalf("a slot whose holder died stayed held: %v", err)
	}
	release()
}

// TestAJobDescendantKeepsTheSlotAfterItsWriterDies is the other half of the
// crash story. A command's write handle can disappear before Windows has
// finished tearing down its jobs. The suspended stub receives a duplicate
// before it is resumed; the child below is a stand-in for a descendant still
// alive after its writer has gone, and a new writer must remain refused until
// that descendant dies.
func TestAJobDescendantKeepsTheSlotAfterItsWriterDies(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	name := fmt.Sprintf("wub-slot-descendant-%d", os.Getpid())
	path := SlotPath(name)

	release, err := Lease(name, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	transfer, cleanup, err := PrepareTransfer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ready := transfer + ".ready"
	t.Setenv(TransferEnv, transfer)
	t.Setenv(slotDescendantNameEnv, name)
	t.Setenv(slotDescendantReadyEnv, ready)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	line, err := syscall.UTF16FromString(syscall.EscapeArg(exe) +
		" -test.run=TestSlotDescendantAdoptsTransferHandle")
	if err != nil {
		t.Fatal(err)
	}
	var startup syscall.StartupInfo
	startup.Cb = uint32(unsafe.Sizeof(startup))
	var created syscall.ProcessInformation
	if err := syscall.CreateProcess(nil, &line[0], nil, nil, false, 0x00000004,
		nil, nil, &startup, &created); err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(created.Thread)
	defer syscall.CloseHandle(created.Process)
	t.Cleanup(func() { killSlotProcess(created.ProcessId) })
	if err := PassTo(path, created.Process, transfer); err != nil {
		killSlotProcess(created.ProcessId)
		t.Fatal(err)
	}
	if r, _, err := procResumeThreadForTest.Call(uintptr(created.Thread)); r == ^uintptr(0) {
		t.Fatalf("resuming the descendant: %v", err)
	}
	if !waitForSlotTestFile(ready, 5*time.Second) {
		t.Fatal("the descendant never proved it inherited the slot handle")
	}
	data, err := os.ReadFile(ready)
	if err != nil {
		t.Fatal(err)
	}
	var grandchildPID uint32
	t.Cleanup(func() { killSlotProcess(grandchildPID) })
	if _, err := fmt.Sscanf(string(data), "%d", &grandchildPID); err != nil {
		t.Fatalf("reading grandchild PID: %v", err)
	}
	if _, err := syscall.WaitForSingleObject(created.Process, 30_000); err != nil {
		t.Fatal(err)
	}
	// The command's writer handle is gone now; only the duplicate adopted by
	// the descendant may keep the writer out from this point onward.
	release()

	if _, err := Lease(name, 150*time.Millisecond); !errors.Is(err, ErrSlotHeld) {
		t.Fatalf("a live descendant released the slot too early: %v", err)
	}

	killSlotProcess(grandchildPID)
	last, err := Lease(name, 5*time.Second)
	if err != nil {
		t.Fatalf("the slot stayed held after its descendant died: %v", err)
	}
	last()
}

const slotHelperEnv = "WUSERBOX_SLOT_HELPER"

const (
	slotDescendantNameEnv  = "WUSERBOX_SLOT_DESCENDANT_NAME"
	slotDescendantReadyEnv = "WUSERBOX_SLOT_DESCENDANT_READY"
)

var procResumeThreadForTest = w32.Kernel32.NewProc("ResumeThread")

// TestSlotHelperTakesTheSlotAndDies is the second process of the test above.
// It does nothing when run as part of an ordinary test run.
func TestSlotHelperTakesTheSlotAndDies(t *testing.T) {
	name := os.Getenv(slotHelperEnv)
	if name == "" {
		t.Skip("runs only as the child of TestASlotFreesWhenItsHolderDies")
	}
	release, err := Lease(name, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = release
	// Dead, holding the slot: no defer runs and no cleanup happens, and the
	// kernel is the only thing that can put the slot back.
	os.Exit(0)
}

// TestSlotDescendantAdoptsTransferHandle is the child in
// TestAJobDescendantKeepsTheSlotAfterItsWriterDies. It models the stub after
// the parent has duplicated the lease into its suspended process.
func TestSlotDescendantAdoptsTransferHandle(t *testing.T) {
	handoff := os.Getenv(TransferEnv)
	name := os.Getenv(slotDescendantNameEnv)
	ready := os.Getenv(slotDescendantReadyEnv)
	if handoff == "" || name == "" || ready == "" {
		t.Skip("runs only as the suspended slot descendant")
	}
	value, err := os.ReadFile(handoff)
	if err != nil {
		t.Fatal(err)
	}
	release, err := Adopt(string(value))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_ = os.Unsetenv(TransferEnv)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	line, err := syscall.UTF16FromString(syscall.EscapeArg(exe) +
		" -test.run=TestSlotGrandchildSeesInheritedHandle")
	if err != nil {
		t.Fatal(err)
	}
	var startup syscall.StartupInfo
	startup.Cb = uint32(unsafe.Sizeof(startup))
	var created syscall.ProcessInformation
	if err := syscall.CreateProcess(nil, &line[0], nil, nil, true, 0,
		nil, nil, &startup, &created); err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(created.Thread)
	defer syscall.CloseHandle(created.Process)
	if !waitForSlotTestFile(ready, 5*time.Second) {
		t.Fatal("the grandchild never proved it inherited the slot handle")
	}
	// The grandchild is now the only holder. Returning lets the parent close
	// the stub's copy before it tries the next writer.
}

func TestSlotGrandchildSeesInheritedHandle(t *testing.T) {
	name := os.Getenv(slotDescendantNameEnv)
	ready := os.Getenv(slotDescendantReadyEnv)
	if name == "" || ready == "" {
		t.Skip("runs only as the inherited-handle grandchild")
	}
	if _, err := Lease(name, 0); !errors.Is(err, ErrSlotHeld) {
		t.Fatalf("the inherited slot handle did not block a writer: %v", err)
	}
	if err := os.WriteFile(ready, []byte(fmt.Sprint(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	// The parent terminates this stand-in after checking that the slot stayed
	// held when both the writer and the stub had gone away.
	time.Sleep(30 * time.Second)
}

func waitForSlotTestFile(path string, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func killSlotProcess(pid uint32) {
	if pid == 0 {
		return
	}
	if process, err := os.FindProcess(int(pid)); err == nil {
		_ = process.Kill()
	}
}
