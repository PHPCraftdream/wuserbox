package lock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/quietexec"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
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

	other := quietexec.Command(os.Args[0], "-test.run=TestSlotHelperTakesTheSlotAndDies")
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

// The paths the stand-ins below are told about through their environment:
// the handoff file carrying the duplicated handle value, the file they write
// their damage attempt's outcome to, and -- for the one that holds -- the
// ready, go and done files that let the test release its own copy while the
// stand-in is still holding what it was handed.
const (
	slotHandoffEnv = "WUSERBOX_SLOT_HANDOFF"
	slotDamageEnv  = "WUSERBOX_SLOT_DAMAGE"
	slotReadyEnv   = "WUSERBOX_SLOT_READY"
	slotGoEnv      = "WUSERBOX_SLOT_GO"
	slotDoneEnv    = "WUSERBOX_SLOT_DONE"
)

// TestALeaseHandedToTheStubCarriesNoRightsOverTheSlotFile pins what a
// handoff is for and nothing more. The exclusion that makes a slot a slot is
// the share mode of the original open, not the access mask of any copy: as
// long as one handle to the file object is open, a second open with share
// mode zero is refused. A duplicate therefore needs no useful access at all
// -- and it must have none, because the source handle is opened
// GENERIC_READ|GENERIC_WRITE and a duplicate that carries that along
// measured able to set FILE_ATTRIBUTE_READONLY on the slot file, which
// bricked every later Lease with "Access is denied" until somebody cleared
// the bit from outside. That is a denial of service a program inside the
// sandbox can inflict on its own sandbox at will, so the duplicate is
// handed over with no access whatsoever, and this is the test that fails if
// its access ever grows back.
func TestALeaseHandedToTheStubCarriesNoRightsOverTheSlotFile(t *testing.T) {
	_, release, outcome, _, _ := handOffToADescendant(t, "")
	// Released before the test ends, so the temp directory can go: the
	// stand-in closed its copy when it reported, and this process must not
	// stand there holding the slot file open beneath the cleanup.
	defer release()
	if !strings.HasPrefix(outcome, "refused") {
		t.Fatalf("the duplicated lease handle could rewrite the slot file: %s", outcome)
	}
}

// TestADuplicateAloneKeepsTheSlotShutAndGivesItBackUnharmed measures both
// halves of the minimal handoff. The writer's own copy is released while the
// adopted duplicate is the only handle left, and a second Lease is still
// refused -- the exclusion was never the duplicate's access mask to lose.
// Then the duplicate closes, and the slot must come back usable: with the
// old same-access duplicate, the damage its holder could do survived every
// handle, and this Lease came back "Access is denied" forever.
func TestADuplicateAloneKeepsTheSlotShutAndGivesItBackUnharmed(t *testing.T) {
	name, release, outcome, goFile, done := handOffToADescendant(t, "hold")
	if !strings.HasPrefix(outcome, "refused") {
		t.Fatalf("the duplicated lease handle could rewrite the slot file, so what follows says nothing: %s", outcome)
	}
	// The writer's own copy is let go here, before anything else is asked
	// of the slot: what remains holding it is the duplicate and nothing
	// else, so the refusal below is the duplicate's doing, not the writer's.
	release()
	if _, err := Lease(name, 150*time.Millisecond); !errors.Is(err, ErrSlotHeld) {
		t.Fatalf("a slot whose only remaining handle was an access-free duplicate let a second writer in: %v", err)
	}
	if err := os.WriteFile(goFile, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !waitForSlotTestFile(done, 5*time.Second) {
		t.Fatal("the stand-in never let go of its duplicate")
	}
	last, err := Lease(name, 5*time.Second)
	if err != nil {
		t.Fatalf("a slot whose duplicate carried no access came back damaged: %v", err)
	}
	last()
}

// handOffToADescendant takes a lease, births a suspended stand-in for the
// stub, and duplicates the lease into it exactly the way a run does: through
// PassTo, before the stand-in has executed one instruction of its own. Mode
// "" has the stand-in make its damage attempt and die; mode "hold" has it
// hold the adopted handle open until the test says go, so the test can
// release its own copy and meet a slot held by the duplicate alone.
func handOffToADescendant(t *testing.T, mode string) (name string, release func(), outcome, goFile, done string) {
	t.Helper()
	t.Setenv("LOCALAPPDATA", t.TempDir())
	name = fmt.Sprintf("wub-slot-handoff-%d", os.Getpid())
	path := SlotPath(name)
	dir := t.TempDir()
	outcomeFile := dir + `\damage.out`
	t.Setenv(slotDamageEnv, outcomeFile)

	if mode == "hold" {
		goFile, done = dir+`\go`, dir+`\done`
		t.Setenv(slotReadyEnv, dir+`\ready`)
		t.Setenv(slotGoEnv, goFile)
		t.Setenv(slotDoneEnv, done)
	}

	release, err := Lease(name, 0)
	if err != nil {
		t.Fatal(err)
	}
	transfer, cleanup, err := PrepareTransfer(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	t.Setenv(slotHandoffEnv, transfer)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	line, err := syscall.UTF16FromString(syscall.EscapeArg(exe) +
		" -test.run=TestSlotDescendantTriesToDamageTheSlot")
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
	t.Cleanup(func() { killSlotProcess(created.ProcessId) })
	if err := PassTo(path, created.Process, transfer); err != nil {
		killSlotProcess(created.ProcessId)
		t.Fatal(err)
	}
	if r, _, err := procResumeThreadForTest.Call(uintptr(created.Thread)); r == ^uintptr(0) {
		t.Fatalf("resuming the stand-in: %v", err)
	}

	if mode == "hold" {
		if !waitForSlotTestFile(dir+`\ready`, 5*time.Second) {
			t.Fatal("the stand-in never proved it adopted the duplicate")
		}
		outcome = readSlotTestFile(t, outcomeFile)
		return name, release, outcome, goFile, done
	}
	if !waitForSlotTestFile(outcomeFile, 5*time.Second) {
		t.Fatal("the stand-in never reported its damage attempt")
	}
	return name, release, readSlotTestFile(t, outcomeFile), "", ""
}

// TestSlotDescendantTriesToDamageTheSlot is the stand-in in the two tests
// above: it adopts the duplicated handle the way Stub adopts the lease, and
// then does the thing a program inside the sandbox was measured able to do
// with a same-access duplicate -- set the read-only attribute on the slot
// file through the handle it was handed. What it may lawfully do with the
// handle it was actually given is refuse; the file it writes says which.
// It does nothing when run as part of an ordinary test run.
func TestSlotDescendantTriesToDamageTheSlot(t *testing.T) {
	handoff := os.Getenv(slotHandoffEnv)
	outcome := os.Getenv(slotDamageEnv)
	if handoff == "" || outcome == "" {
		t.Skip("runs only as the suspended slot descendant")
	}
	value, err := os.ReadFile(handoff)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(value)), 10, 64)
	if err != nil || n == 0 || uint64(uintptr(n)) != n {
		t.Fatalf("the handoff did not carry a handle value: %v", err)
	}
	handle := syscall.Handle(uintptr(n))

	var info slotFileBasicInfoForTest
	info.attributes = fileAttributeReadonlyForTest
	if r, _, callErr := procSetFileBasicInfoForTest.Call(uintptr(handle), fileBasicInfoClassForTest,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); r != 0 {
		writeSlotTestFile(t, outcome, "succeeded")
	} else {
		writeSlotTestFile(t, outcome, "refused: "+callErr.Error())
	}

	ready, goFile, done := os.Getenv(slotReadyEnv), os.Getenv(slotGoEnv), os.Getenv(slotDoneEnv)
	if ready == "" {
		syscall.CloseHandle(handle)
		return
	}
	// Held open until told otherwise, so the test can release its own copy
	// and find the slot still shut with the duplicate holding it alone.
	writeSlotTestFile(t, ready, "ready")
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(goFile); err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			writeSlotTestFile(t, done, "never told to go")
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	syscall.CloseHandle(handle)
	writeSlotTestFile(t, done, "done")
}

// SetFileInformationByHandle against a file's basic information, spelled out
// here because setting FILE_ATTRIBUTE_READONLY through a handle is the one
// damage a write-access duplicate was measured able to do.
const (
	fileBasicInfoClassForTest    = uintptr(0)
	fileAttributeReadonlyForTest = 0x00000001
)

// slotFileBasicInfoForTest mirrors FILE_BASIC_INFO: only FileAttributes is
// set, and the time fields are left zero, which SetFileInformationByHandle
// reads as "leave unchanged".
type slotFileBasicInfoForTest struct {
	creation, lastAccess, lastWrite, change int64
	attributes                              uint32
	pad                                     uint32
}

var procSetFileBasicInfoForTest = w32.Kernel32.NewProc("SetFileInformationByHandle")

var procResumeThreadForTest = w32.Kernel32.NewProc("ResumeThread")

func writeSlotTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readSlotTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// waitForSlotTestFile waits for one stage of a chain to say something, and
// waits for what it said rather than for the file it said it in.
//
// The distinction is the whole of this function and it was learned the hard
// way. Every one of these files is written by os.WriteFile, which creates
// the file and then writes it, so between those two a reader polling Stat
// sees a file that exists and holds nothing. Measured under `go test ./...`,
// which runs a package per core: the stub's handoff file was read back empty
// and the chain's pids came out "EOF", failing a test about lease ordering
// for a reason that has nothing to do with leases, in roughly one full-suite
// run in two. A partial read is worse than an empty one and was the real
// danger here: "11844 1" parses as two perfectly good numbers, and the
// second is a pid this test would then have killed.
//
// Emptiness is the signal because every writer here writes something. A
// caller that needs the content to parse, and not merely to be there, waits
// on the parse itself -- see waitForSlotChainPIDs.
func waitForSlotTestFile(path string, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
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

// TestASlotFileIsBeyondTheReadGrantThatReachesItsDirectory pins the answer to
// the review-round-ten finding. The state directory sits inside the profile,
// and the home-wide read grant reaches everything in it, so what keeps a
// sandbox from opening a slot file has to be the file's own permission list
// and not the directory's. Everyone stands in for the read group here --
// creating the real one needs the elevation only --init carries -- playing
// the same part: an inheritable read grant on the directory the slot files
// live in, held by an identity a sandbox runs as.
func TestASlotFileIsBeyondTheReadGrantThatReachesItsDirectory(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	dir := paths.StateDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := acl.Set(dir, sid.Everyone, []acl.ACE{
		{Access: acl.AccessReadExecute, Inheritance: acl.InheritObjects | acl.InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("wub-slot-grant-%d", os.Getpid())

	release, err := Lease(name, 0)
	if err != nil {
		t.Fatal(err)
	}
	if acl.Reads(SlotPath(name), sid.Everyone) {
		release()
		t.Fatalf("the read grant on %s reaches the slot file behind it, so a sandbox could open -- and with the open hold -- the lease", dir)
	}
	release()

	// The list must shut the sandbox out and nobody else: every take
	// reopens the file by name, and a list that shut its own owner out
	// would brick the next run the way a stray read-only bit once did.
	again, err := Lease(name, 5*time.Second)
	if err != nil {
		t.Fatalf("a slot file the lease's own owner cannot reopen: %v", err)
	}
	again()
}
