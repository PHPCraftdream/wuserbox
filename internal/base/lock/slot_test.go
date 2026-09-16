package lock

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
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

const slotHelperEnv = "WUSERBOX_SLOT_HELPER"

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
