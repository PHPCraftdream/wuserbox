// The crash story of the lease, measured on the real shape instead of a
// model of it: an outer process holding the lease, a kill-on-close job
// holding a stub that adopted the duplicate, a second kill-on-close job
// holding the program -- and the outer killed outright, with no cleanup
// running anywhere.
//
// The package cannot import internal/win/proc for the job, because proc
// imports this package, so the job is re-created here exactly the way
// newJob builds it; the comment on that function explains why the extended
// limit class is the one that works.
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

	"github.com/PHPCraftdream/wuserbox/internal/win/quietexec"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// The facts the three stand-ins below are told through their environment:
// which slot the chain holds, where the stub announces its pid and the
// program's, and where the stub reports whether the duplicate it adopted is
// inheritable -- the one fact that decides whether a copy of the lease can
// reach the program at all.
const (
	slotChainNameEnv  = "WUSERBOX_SLOT_CHAIN_NAME"
	slotChainReadyEnv = "WUSERBOX_SLOT_CHAIN_READY"
	slotChainFlagsEnv = "WUSERBOX_SLOT_CHAIN_FLAGS"
)

type chainBasicLimits struct {
	perProcessUserTimeLimit int64
	perJobUserTimeLimit     int64
	limitFlags              uint32
	minimumWorkingSetSize   uintptr
	maximumWorkingSetSize   uintptr
	activeProcessLimit      uint32
	affinity                uintptr
	priorityClass           uint32
	schedulingClass         uint32
}

type chainIOCounters struct {
	readOperationCount  uint64
	writeOperationCount uint64
	otherOperationCount uint64
	readTransferCount   uint64
	writeTransferCount  uint64
	otherTransferCount  uint64
}

type chainExtendedLimits struct {
	basic                 chainBasicLimits
	io                    chainIOCounters
	processMemoryLimit    uintptr
	jobMemoryLimit        uintptr
	peakProcessMemoryUsed uintptr
	peakJobMemoryUsed     uintptr
}

const (
	chainKillOnJobClose            = 0x00002000
	chainJobExtendedLimitInfoClass = 9
	// HANDLE_FLAG_INHERIT, the flag whose absence keeps a copy of the lease
	// out of the program.
	chainHandleFlagInherit = 0x00000001
)

var (
	procCreateJobForChain     = w32.Kernel32.NewProc("CreateJobObjectW")
	procSetJobInfoForChain    = w32.Kernel32.NewProc("SetInformationJobObject")
	procAssignJobForChain     = w32.Kernel32.NewProc("AssignProcessToJobObject")
	procResumeThreadForChain  = w32.Kernel32.NewProc("ResumeThread")
	procOpenProcessForChain   = w32.Kernel32.NewProc("OpenProcess")
	procGetHandleInfoForChain = w32.Kernel32.NewProc("GetHandleInformation")
)

type chainJob struct{ handle syscall.Handle }

func newKillOnCloseJobForChain(t *testing.T) *chainJob {
	t.Helper()
	r, _, callErr := procCreateJobForChain.Call(0, 0)
	if r == 0 {
		t.Fatalf("creating the chain's job: %v", callErr)
	}
	handle := syscall.Handle(r)
	var info chainExtendedLimits
	info.basic.limitFlags = chainKillOnJobClose
	if r, _, callErr := procSetJobInfoForChain.Call(uintptr(handle), chainJobExtendedLimitInfoClass,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); r == 0 {
		syscall.CloseHandle(handle)
		t.Fatalf("setting kill-on-close on the chain's job: %v", callErr)
	}
	return &chainJob{handle: handle}
}

func (j *chainJob) close() { syscall.CloseHandle(j.handle) }

func (j *chainJob) assign(process syscall.Handle) error {
	if r, _, callErr := procAssignJobForChain.Call(uintptr(j.handle), uintptr(process)); r == 0 {
		return callErr
	}
	return nil
}

// chainProcessGone answers whether pid is gone, and keeps asking until the
// wait runs out. A dead process answers in microseconds; the bound exists
// so a live one fails the test instead of hanging it.
func chainProcessGone(pid uint32, wait time.Duration) bool {
	const synchronize = 0x00100000
	deadline := time.Now().Add(wait)
	for {
		h, _, _ := procOpenProcessForChain.Call(synchronize, 0, uintptr(pid))
		if h == 0 {
			return true
		}
		r, _ := syscall.WaitForSingleObject(syscall.Handle(h), 0)
		syscall.CloseHandle(syscall.Handle(h))
		if r == 0 {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTheProgramCarriesNoLeaseAndCannotOutliveItsStub pins the decision the
// crash story forced. A probe had the program close its inherited copy of
// the lease and keep running, and a fresh Lease succeeded while it lived --
// but that probe built no jobs. With the real chain the program cannot
// outlive its stub: killing the outer closes the first job, which ends the
// stub, whose death closes the second job's last handle, which ends the
// program. Measured here, below, on real jobs and a real kill.
//
// The stub is asked whether the duplicate it adopted carries the inherit
// flag because the program is started with inheritance on, the way proc.Run
// starts one -- so if the duplicate were inheritable, a copy of the lease
// would reach the program. The answer must be no: the program is handed
// nothing. It is asked where the handle actually lives, in the stub, rather
// than by poking the value from inside the program, where a fresh process
// can hold an unrelated handle worth the same number. This is the test that
// fails if the duplicate ever turns inheritable, and it holds the kernel's
// answer -- the program dies with its stub, and the kernel gives the slot
// back -- where nothing can quietly stop resting on it. The zero-access half
// lives in the two damage tests.
func TestTheProgramCarriesNoLeaseAndCannotOutliveItsStub(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	name := fmt.Sprintf("wub-slot-chain-%d", os.Getpid())
	dir := t.TempDir()
	ready, flags := dir+`\chain.ready`, dir+`\chain.flags`
	t.Setenv(slotChainNameEnv, name)
	t.Setenv(slotChainReadyEnv, ready)
	t.Setenv(slotChainFlagsEnv, flags)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := quietexec.Command(exe, "-test.run=TestSlotChainOuterHoldsTheChainAndWaits")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		killSlotProcess(uint32(cmd.Process.Pid))
		_ = cmd.Wait() // the only answer a killed process gives is the kill
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

	if _, err := Lease(name, 150*time.Millisecond); !errors.Is(err, ErrSlotHeld) {
		t.Fatalf("a chain holding the lease let a second writer in while it was alive: %v", err)
	}
	if !waitForSlotTestFile(flags, 10*time.Second) {
		t.Fatal("the stub of the chain never reported whether its duplicate is inheritable")
	}
	if got := readSlotTestFile(t, flags); got != "plain" {
		t.Fatalf("the stub's adopted duplicate is inheritable (%s), so the program inherits a copy of the lease and is handed something after all", got)
	}

	// Killed outright, like wuserbox with the power pulled: no cleanup runs
	// anywhere below it, and the jobs are what answer for everything.
	killSlotProcess(uint32(cmd.Process.Pid))
	_ = cmd.Wait()
	stubGone := chainProcessGone(stubPID, 10*time.Second)
	programGone := chainProcessGone(programPID, 10*time.Second)
	if !stubGone || !programGone {
		t.Fatalf("something in the chain outlived the process that died: stub gone %v, program gone %v",
			stubGone, programGone)
	}
	last, err := Lease(name, 5*time.Second)
	if err != nil {
		t.Fatalf("the kernel never gave the slot back after the whole chain died: %v", err)
	}
	last()
}

// TestSlotChainOuterHoldsTheChainAndWaits is the outer wuserbox of the chain
// test: it takes the lease, births the suspended stub in a kill-on-close
// job, duplicates the lease into it and resumes it -- a run's launch, on the
// same calls. It is killed while it waits, which is the point of it.
func TestSlotChainOuterHoldsTheChainAndWaits(t *testing.T) {
	name := os.Getenv(slotChainNameEnv)
	ready := os.Getenv(slotChainReadyEnv)
	if name == "" || ready == "" {
		t.Skip("runs only as the outer of the chain test")
	}
	path := SlotPath(name)
	// Taken before anything else, the way holdSlot takes it: the lease's
	// first open is what creates the state directory the handoff file below
	// lands in. And in the normal mode never released on purpose -- the
	// outer of the chain dies holding the lease, the way a killed wuserbox
	// does, and the kernel is what puts the slot back. Only the negative
	// control asks for an early release, below.
	release, err := Lease(name, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = release
	transfer, cleanup, err := PrepareTransfer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	t.Setenv(TransferEnv, transfer)
	j := newKillOnCloseJobForChain(t)
	defer j.close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	line, err := syscall.UTF16FromString(syscall.EscapeArg(exe) +
		" -test.run=TestSlotChainStubAdoptsTheLeaseAndStartsAProgram")
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
	if err := j.assign(created.Process); err != nil {
		killSlotProcess(created.ProcessId)
		t.Fatal(err)
	}
	// The handoff a real run makes: into the suspended stub, before it has
	// executed one instruction of its own.
	if err := PassTo(path, created.Process, transfer); err != nil {
		killSlotProcess(created.ProcessId)
		t.Fatal(err)
	}
	if r, _, callErr := procResumeThreadForChain.Call(uintptr(created.Thread)); r == ^uintptr(0) {
		t.Fatalf("resuming the stub of the chain: %v", callErr)
	}
	if !waitForSlotTestFile(ready, 15*time.Second) {
		t.Fatal("the stub of the chain never became ready")
	}
	// The negative control asks the outer to let its copy go once the chain
	// stands, so the slot can come free while the program is demonstrably
	// beating. The stub's duplicate must go too -- the slot only comes free
	// when both handles are closed -- and the stub does the same, below. It
	// cannot go earlier: PassTo duplicates from held.byPath and needs the
	// lease still held by this process.
	if os.Getenv(slotChainReleaseEnv) == "1" {
		chainWaitForGo(t, os.Getenv(slotChainGoEnv))
		release()
	}
	time.Sleep(60 * time.Second)
}

// TestSlotChainStubAdoptsTheLeaseAndStartsAProgram is the stub of the chain
// test: it adopts the duplicated lease the way Stub adopts the real handoff,
// reports whether what it is holding is inheritable, puts the program in a
// kill-on-close job of its own, and starts it the way proc.Run starts one --
// suspended, assigned, resumed, with handle inheritance on, so everything
// inheritable in this process reaches it.
func TestSlotChainStubAdoptsTheLeaseAndStartsAProgram(t *testing.T) {
	transfer := os.Getenv(TransferEnv)
	ready := os.Getenv(slotChainReadyEnv)
	flags := os.Getenv(slotChainFlagsEnv)
	if transfer == "" || ready == "" || flags == "" {
		t.Skip("runs only as the stub of the chain test")
	}
	value, err := os.ReadFile(transfer)
	if err != nil {
		t.Fatal(err)
	}
	release, err := Adopt(string(value))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	n, err := strconv.ParseUint(strings.TrimSpace(string(value)), 10, 64)
	if err != nil || n == 0 || uint64(uintptr(n)) != n {
		t.Fatalf("the handoff did not carry a handle value: %v", err)
	}
	var got uint32
	if r, _, _ := procGetHandleInfoForChain.Call(uintptr(n), uintptr(unsafe.Pointer(&got))); r == 0 {
		t.Fatal("the adopted duplicate could not be asked for its flags")
	}
	if got&chainHandleFlagInherit != 0 {
		writeSlotTestFile(t, flags, "inherit")
	} else {
		writeSlotTestFile(t, flags, "plain")
	}
	j := newKillOnCloseJobForChain(t)
	defer j.close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	line, err := syscall.UTF16FromString(syscall.EscapeArg(exe) +
		" -test.run=TestSlotChainProgramStandsThere")
	if err != nil {
		t.Fatal(err)
	}
	var startup syscall.StartupInfo
	startup.Cb = uint32(unsafe.Sizeof(startup))
	var created syscall.ProcessInformation
	// bInheritHandles on, the way Run starts the program: whatever is
	// inheritable here reaches it, and nothing else decides what does.
	if err := syscall.CreateProcess(nil, &line[0], nil, nil, true, 0x00000004,
		nil, nil, &startup, &created); err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(created.Thread)
	defer syscall.CloseHandle(created.Process)
	t.Cleanup(func() { killSlotProcess(created.ProcessId) })
	if err := j.assign(created.Process); err != nil {
		killSlotProcess(created.ProcessId)
		t.Fatal(err)
	}
	if r, _, callErr := procResumeThreadForChain.Call(uintptr(created.Thread)); r == ^uintptr(0) {
		t.Fatalf("resuming the program of the chain: %v", callErr)
	}
	if err := os.WriteFile(ready, []byte(fmt.Sprintf("%d %d", os.Getpid(), created.ProcessId)), 0o600); err != nil {
		t.Fatal(err)
	}
	// The negative control's other half: the adopted duplicate goes too, so
	// both handles holding the slot are closed while the program runs.
	// Adopt's release is idempotent, so the defer above stays.
	if os.Getenv(slotChainReleaseEnv) == "1" {
		chainWaitForGo(t, os.Getenv(slotChainGoEnv))
		release()
	}
	if _, err := syscall.WaitForSingleObject(created.Process, syscall.INFINITE); err != nil {
		t.Fatal(err)
	}
}

// TestSlotChainProgramStandsThere is the program at the end of the chain,
// untrusted by construction and handed nothing by the handoff. It stands
// there running -- the thing a program of a run is doing while the world
// around it is torn down -- and what the test measures is whether it is
// still alive once its stub is gone.
func TestSlotChainProgramStandsThere(t *testing.T) {
	if os.Getenv(slotChainFlagsEnv) == "" {
		t.Skip("runs only as the program at the end of the chain test")
	}
	// The heartbeat branch: a program that is provably executing, so the
	// grant test can compare the last executed instruction's timestamp with
	// the instant the slot comes free. It never returns; the job ends it.
	if section := os.Getenv(slotChainBeatEnv); section != "" {
		chainRunHeartbeat(t, section)
	}
	time.Sleep(60 * time.Second)
}
