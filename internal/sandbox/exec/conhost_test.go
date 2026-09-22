// The console-host shut measured from the seat the wiring is answerable to.
// What the production code promises is not only that ShieldConhost shuts a
// host it is handed (internal/win/proc measures that from a restricted
// token's seat) but that takeConsoleRelay, on every call, picks the one host
// its own CreatePseudoConsole created out of whatever conhosts this process
// already has, and hands it to ShieldConhost before the relay is handed back.
// That seam is what this file holds to the doors the review's P0-1 measured
// open.
//
// The seat is built in account_test.go: a dedicated local account, this
// binary started as it with RunAsAccount -- the launch a real run gives its
// stub -- and the choreography below runs inside that child. The measurement
// helpers therefore return errors rather than failing a testing.T -- the
// process they run in has none -- and the test at the bottom is thin: it
// builds the seat, starts the child, and reads the verdict from its exit
// code.

package exec

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	// The walks and opens this test needs, under fresh names: the prowler's
	// test file in internal/win/proc already claims procOpenProcess in its
	// own package, and two LazyProcs for one entry point cannot share a
	// package -- the same reason conhost.go needed procOpenAnotherProcess.
	procOpenProcessInExec              = w32.Kernel32.NewProc("OpenProcess")
	procCreateToolhelp32SnapshotInExec = w32.Kernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32FirstInExec            = w32.Kernel32.NewProc("Thread32First")
	procThread32NextInExec             = w32.Kernel32.NewProc("Thread32Next")
	procOpenThreadInExec               = w32.Kernel32.NewProc("OpenThread")
)

// The access masks the review's P0-1 probe measured, restated here as locals:
// a _test file's identifiers cannot be imported, so every number this test
// asserts against is named at the top where it can be checked against the
// review and the prowler rather than buried at its use.
const (
	// Process masks. PROCESS_ALL_ACCESS is the door the review measured wide
	// open on an unshielded host; the rest are the single rights a shut has
	// to take away one at a time, because a refusal of a set is not a
	// refusal of its members.
	processAllAccess      = 0x1FFFFF   // PROCESS_ALL_ACCESS
	processCreateThread   = 0x0002     // PROCESS_CREATE_THREAD
	processVMOperation    = 0x0008     // PROCESS_VM_OPERATION
	processVMWrite        = 0x0020     // PROCESS_VM_WRITE
	processDupHandle      = 0x0040     // PROCESS_DUP_HANDLE
	processSetInformation = 0x0200     // PROCESS_SET_INFORMATION
	processQueryLimited   = 0x1000     // PROCESS_QUERY_LIMITED_INFORMATION
	writeDac              = 0x00040000 // WRITE_DAC

	// The thread's own doors: THREAD_SET_CONTEXT with
	// THREAD_SUSPEND_RESUME is the beginning of redirecting instructions,
	// and WRITE_DAC on a thread is the right that rewrites its list.
	threadSetContext    = 0x0010 // THREAD_SET_CONTEXT
	threadSuspendResume = 0x0002 // THREAD_SUSPEND_RESUME

	// The Toolhelp walk that finds one thread of the host, in the raw-offset
	// shape internal/win/proc's shutThreadsAlreadyRunning uses: a
	// THREADENTRY32 is 28 bytes, the thread id sits at offset 8, the owning
	// process id at 12, and the walk ends with ERROR_NO_MORE_FILES (18).
	snapshotOfThreads  = 0x00000004 // TH32CS_SNAPTHREAD
	threadEntrySize    = 28
	threadIDOffset     = 8
	ownerProcessOffset = 12
	errNoMoreItems     = 18

	invalidHandle = ^uintptr(0)
)

// aBarePtyOfOurs gives this process a console host of its own, the same
// shape internal/win/proc/conhost_test.go's aConhostOfOurs stands one up
// in: ConsoleHostChildren's before-list, two pipe pairs, CreatePseudoConsole
// with the packed 80x25 COORD the package's own coordValue produces -- the
// same packing expression takeConsoleRelay hands it, so test and production
// cannot drift -- and this process's own copies of the input-read and
// output-write ends closed the moment CreatePseudoConsole returns, which
// duplicates what it needs. Exactly one new pid is tolerated: anything else
// means the walk cannot tell this process's host from a stranger's, and
// nothing measured against a wrong pid would mean anything.
//
// Nothing is ever attached to the console, so the output drain sits idle; it
// exists so a host that did write could never block on a full pipe. The host
// is left alive when the helper returns -- the caller decides when its
// console ends, through closeAConhost behind a heldHost's one-time close.
// The pipe ends kept open outlive the call on purpose: the drain ends when
// the host does, because the host holds the last write end, and the handles
// themselves die with this process -- a fixture child's, moments later.
func aBarePtyOfOurs() (syscall.Handle, uint32, error) {
	before, err := proc.ConsoleHostChildren(uint32(syscall.Getpid()))
	if err != nil {
		return 0, 0, err
	}
	ptyInRead, ptyInWrite, err := os.Pipe()
	if err != nil {
		return 0, 0, err
	}
	ptyOutRead, ptyOutWrite, err := os.Pipe()
	if err != nil {
		ptyInRead.Close()
		ptyInWrite.Close()
		return 0, 0, err
	}
	var hpc syscall.Handle
	r, _, callErr := procCreatePseudoConsole.Call(coordValue(80, 25), ptyInRead.Fd(), ptyOutWrite.Fd(), 0,
		uintptr(unsafe.Pointer(&hpc)))
	ptyInRead.Close()
	ptyOutWrite.Close()
	if r != 0 {
		ptyInWrite.Close()
		ptyOutRead.Close()
		return 0, 0, fmt.Errorf("CreatePseudoConsole: hresult 0x%x (%w)", r, callErr)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := ptyOutRead.Read(buf); err != nil {
				return
			}
		}
	}()
	after, err := proc.ConsoleHostChildren(uint32(syscall.Getpid()))
	if err != nil {
		procClosePseudoConsole.Call(uintptr(hpc))
		ptyInWrite.Close()
		ptyOutRead.Close()
		return 0, 0, err
	}
	var fresh []uint32
	for _, pid := range after {
		if !slices.Contains(before, pid) {
			fresh = append(fresh, pid)
		}
	}
	if len(fresh) != 1 {
		procClosePseudoConsole.Call(uintptr(hpc))
		ptyInWrite.Close()
		ptyOutRead.Close()
		return 0, 0, fmt.Errorf("creating a bare pseudo console did not leave exactly one new console host: "+
			"before %v, after %v", before, after)
	}
	return hpc, fresh[0], nil
}

// canOpenRaw answers the one question an access mask asks: could this
// process's own token open pid for access? A nonzero handle is yes, and is
// closed at once; zero is no. There is no error channel -- the bool is the
// whole answer, because the difference between "refused" and "refused for a
// stranger reason" is not a distinction this measurement acts on.
func canOpenRaw(pid uint32, access uintptr) bool {
	handle, _, _ := procOpenProcessInExec.Call(access, 0, uintptr(pid))
	if handle == 0 {
		return false
	}
	syscall.CloseHandle(syscall.Handle(handle))
	return true
}

// closeAConhost tears down what aBarePtyOfOurs built: the pseudo console,
// whose host dies with it.
//
// The close is one-time, and the caller may already have made it -- the
// standing host outlives the relay's creation on purpose. A handle whose
// object has gone back to the table may name something else by then, so the
// host's presence in this process's own walk -- parentage and name, the same
// test ConsoleHostChildren exists for -- is what says the close is still ours
// to make. A walk that errors says nothing either way, and there the
// ordinary case is a host still to shut.
func closeAConhost(hpc syscall.Handle, pid uint32) {
	ours := true
	if hosts, err := proc.ConsoleHostChildren(uint32(syscall.Getpid())); err == nil {
		ours = false
		for _, host := range hosts {
			if host == pid {
				ours = true
				break
			}
		}
	}
	if ours {
		procClosePseudoConsole.Call(uintptr(hpc))
	}
}

// heldHost carries one host's close so measureTheRelayShut can reach it from
// the explicit close after the doors and the deferred one every error return
// runs through, while keeping that close one-time: after the first, the pid
// is forgotten, so no second call can reach closeAConhost with a handle
// value whose host is already gone -- the accident the walk guard exists to
// prevent, kept from ever being made.
type heldHost struct {
	hpc syscall.Handle
	pid uint32
}

func (h *heldHost) close() {
	if h.pid == 0 {
		return
	}
	closeAConhost(h.hpc, h.pid)
	h.pid = 0
}

// The fixture child is born by RunAsAccount with CREATE_NO_WINDOW, so it has
// a birth console host of its own that shows up in ConsoleHostChildren's
// walk late -- measured about 150 ms after the process it hosts, the lag
// console.go documents. The before/after diffs that name the relay's host
// must not mistake that late arrival for the host the relay created, so the
// choreography waits for the walk to settle first, polling this often, for
// at most this long -- the same step and ceiling console.go polls it with.
const (
	hostWalkPollStep = 25 * time.Millisecond
	hostWalkPollWant = 3 * time.Second
)

// waitUntilHostWalkSettles polls ConsoleHostChildren until two walks a step
// apart answer the same list, which is the only observable meaning "the birth
// host has arrived" has here. A walk that keeps changing to the end of the
// ceiling is refused, with the lists it was still seeing, because a diff
// taken against an unsettled walk would measure the wrong host.
func waitUntilHostWalkSettles() error {
	last, err := proc.ConsoleHostChildren(uint32(syscall.Getpid()))
	if err != nil {
		return err
	}
	deadline := time.Now().Add(hostWalkPollWant)
	for {
		time.Sleep(hostWalkPollStep)
		now, err := proc.ConsoleHostChildren(uint32(syscall.Getpid()))
		if err != nil {
			return err
		}
		if samePids(now, last) {
			return nil
		}
		last = now
		if time.Now().After(deadline) {
			return fmt.Errorf("the console host walk never settled within %v: %v then %v",
				hostWalkPollWant, last, now)
		}
	}
}

func samePids(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// relayFixtureFlag dispatches the fixture child to the relay's choreography.
const relayFixtureFlag = "-wuserbox-relay-fixture"

// relayFixture is the program this binary becomes when it is started as the
// fixture account. The exit code is the verdict and diagnosis.txt is the
// words that explain a failure -- the split the account fixture works on,
// because the file is the one thing a refusal elsewhere cannot take away.
func relayFixture(dir string) int {
	if err := measureTheRelayShut(dir); err != nil {
		return fixtureFailed(dir, err)
	}
	return 0
}

// measureTheRelayShut is the wiring test's whole choreography, in the
// account's seat: the walk is settled, the controls are measured open, the
// relay is taken, and the host it created is measured shut, door by door.
// Every old Fatalf and Errorf is a returned error carrying the same words,
// and the leaking doors are collected into one error -- the old test's
// accumulated t.Errorf, which a fixture child has no testing.T to accumulate
// with and one CI run must say everything.
func measureTheRelayShut(dir string) error {
	if err := procCreatePseudoConsole.Find(); err != nil {
		return fmt.Errorf("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+): %w", err)
	}
	// SEAT CONTROL. The seat here is the fixture account's ordinary token,
	// and a fresh local account is never an administrator unless the fixture
	// made it one -- this fixture does not; the assertion keeps the
	// measurement honest if that ever changes.
	if token.IsAdmin() {
		return errors.New("from an elevated seat the shut's deliberate administrators allow " +
			"answers every door by design, so nothing below would be a measurement")
	}
	// The birth host arrives late; every diff below needs the walk settled.
	if err := waitUntilHostWalkSettles(); err != nil {
		return err
	}
	ownPid := uint32(syscall.Getpid())

	// CONTROL, and first the walk itself: a CREATE_NO_WINDOW process has a
	// birth console's host of its own, spawned by the launch machinery, and
	// once the walk has settled it must answer exactly one. The birth host
	// is the one console host this process can name, and the object the
	// launch does not touch, so the positive control below needs it pinned
	// before anything is measured against it.
	hosts, err := proc.ConsoleHostChildren(ownPid)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("a CREATE_NO_WINDOW process has a birth console's host; " +
			"the walk answering none is a walk that has not caught up")
	}
	if len(hosts) != 1 {
		return fmt.Errorf("this process has %d console hosts (%v) where its own birth console can have one; "+
			"nothing measured against a walk this crowded would mean anything", len(hosts), hosts)
	}

	// CONTROL: can this seat open something at all. The birth host carries
	// the account's ordinary default list, which grants the account itself
	// everything, so its door must open -- and it is the one object the
	// launch has not shut, which is why the question moved here from this
	// process's own object.
	if !canOpenRaw(hosts[0], processAllAccess) {
		return fmt.Errorf("the birth console's host (%d) refuses this account everything, so the seat's opens "+
			"would not be answered and the refusals measured below would mean nothing", hosts[0])
	}

	// CONTROL, and the direction inverted on purpose: the launch that started
	// this fixture narrows every stub process to the account before its first
	// instruction (internal/win/proc's narrowBeforeResume applies the same
	// deny-first list Shield applies from inside, and its deny names the
	// account itself, which the account is never an administrator to have an
	// allow answer), so this open must be refused -- the shut the launch
	// applies is part of the seat, and from a seat whose own door stands open
	// this would not be the seat a real run measures from. The refusal is
	// pinned so a launch that stops narrowing its stubs is caught here rather
	// than silently measured from.
	if canOpenRaw(ownPid, processAllAccess) {
		return errors.New("this process's own process object opened for everything, but the launch that started " +
			"this fixture narrows every stub process to the account before its first instruction " +
			"(internal/win/proc's narrowBeforeResume), so from a seat whose own door stands open this would " +
			"not be the seat a real run measures from")
	}

	// CONTROL: the door the review measured open on an unshielded host.
	pty, barePid, err := aBarePtyOfOurs()
	if err != nil {
		return err
	}
	bare := &heldHost{hpc: pty, pid: barePid}
	defer bare.close()
	if !canOpenRaw(barePid, processAllAccess) {
		return fmt.Errorf("an unshielded console host (%d) already refuses this account everything, "+
			"so nothing below is measuring the fix", barePid)
	}

	relayBefore, err := proc.ConsoleHostChildren(ownPid)
	if err != nil {
		return err
	}
	relay, err := takeConsoleRelay()
	if err != nil {
		return err
	}
	defer relay.close()
	relayAfter, err := proc.ConsoleHostChildren(ownPid)
	if err != nil {
		return err
	}
	// The same diff production takes, taken here to name the host the relay
	// must have shut: the bare pty's conhost stands in both of these lists
	// too, and cancels out of this one exactly as it cancels out of
	// takeConsoleRelay's own.
	var fresh []uint32
	for _, pid := range relayAfter {
		if !slices.Contains(relayBefore, pid) {
			fresh = append(fresh, pid)
		}
	}
	if len(fresh) != 1 {
		return fmt.Errorf("takeConsoleRelay did not leave exactly one new console host: before %v, after %v, "+
			"the bare pty's host %d", relayBefore, relayAfter, barePid)
	}
	hostPid := fresh[0]

	// The doors, one right at a time -- a refusal of a set is not a refusal
	// of its members, the lesson the prowler's first draft recorded. These
	// are the review's door list -- VM_WRITE, VM_OPERATION, CREATE_THREAD,
	// DUP_HANDLE, WRITE_DAC, thread context -- and each is the beginning of
	// running code in the host or wearing its token: memory you can write
	// and threads you can start or redirect are code inside the host, a
	// handle you can duplicate reaches everything the host holds (its token
	// first), and WRITE_DAC is the right that rewrites the very list meant
	// to refuse you. QUERY_LIMITED and SET_INFORMATION are measured beside
	// them because the review's probe measured them, and QUERY_LIMITED is
	// the sharpest single answer: even the read every process hands out to
	// bystanders is refused here. PROCESS_CREATE_PROCESS is left out
	// deliberately -- it was not one of the review's measured doors, and
	// this test asserts only values it can point at.
	var leaked []string
	for _, door := range []struct {
		name   string
		access uintptr
	}{
		{"PROCESS_ALL_ACCESS", processAllAccess},
		{"PROCESS_CREATE_THREAD", processCreateThread},
		{"PROCESS_VM_OPERATION", processVMOperation},
		{"PROCESS_VM_WRITE", processVMWrite},
		{"PROCESS_DUP_HANDLE", processDupHandle},
		{"PROCESS_SET_INFORMATION", processSetInformation},
		{"PROCESS_QUERY_LIMITED_INFORMATION", processQueryLimited},
		{"WRITE_DAC", writeDac},
	} {
		if canOpenRaw(hostPid, door.access) {
			leaked = append(leaked, fmt.Sprintf("the console host takeConsoleRelay created (%d) let this account in for %s; "+
				"the shut was meant to close that door", hostPid, door.name))
		}
	}

	// And one door the process masks cannot ask about, a thread of its own:
	// instructions you can redirect run inside the host whatever its process
	// list says, so the shut reaches the host's threads as well, and this
	// measures one of them. The walk is the raw-offset Toolhelp shape
	// internal/win/proc's shutThreadsAlreadyRunning uses, restated rather
	// than imported -- a _test file's identifiers cannot be imported.
	snapshot, _, callErr := procCreateToolhelp32SnapshotInExec.Call(snapshotOfThreads, 0)
	if snapshot == 0 || snapshot == invalidHandle {
		return fmt.Errorf("listing the threads of console host %d: %w", hostPid, callErr)
	}
	entry := make([]byte, threadEntrySize)
	*(*uint32)(unsafe.Pointer(&entry[0])) = threadEntrySize
	var tid uint32
	for step := procThread32FirstInExec; ; step = procThread32NextInExec {
		r, _, listErr := step.Call(snapshot, uintptr(unsafe.Pointer(&entry[0])))
		if r == 0 {
			if errors.Is(listErr, syscall.Errno(errNoMoreItems)) {
				break
			}
			syscall.CloseHandle(syscall.Handle(snapshot))
			return fmt.Errorf("walking the threads of console host %d: %w", hostPid, listErr)
		}
		if *(*uint32)(unsafe.Pointer(&entry[ownerProcessOffset])) != hostPid {
			continue
		}
		tid = *(*uint32)(unsafe.Pointer(&entry[threadIDOffset]))
		break
	}
	syscall.CloseHandle(syscall.Handle(snapshot))
	if tid == 0 {
		return fmt.Errorf("no thread of console host %d was found; a running process has threads, "+
			"so the listing answered about somebody else", hostPid)
	}
	for _, door := range []struct {
		name   string
		access uintptr
	}{
		{"THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME", threadSetContext | threadSuspendResume},
		{"WRITE_DAC", writeDac},
	} {
		if handle, _, _ := procOpenThreadInExec.Call(door.access, 0, uintptr(tid)); handle != 0 {
			syscall.CloseHandle(syscall.Handle(handle))
			leaked = append(leaked, fmt.Sprintf("a thread of the console host (%d) was open for %s; "+
				"redirecting or rewriting a thread is running code in the host", hostPid, door.name))
		}
	}
	if len(leaked) != 0 {
		return errors.New(strings.Join(leaked, "; "))
	}

	// The measurement is done: the relay's host is ended, and the bare pty's
	// console follows through its one-time close -- the deferred calls above
	// find both already closed, which is what makes them no-ops rather than
	// second closes.
	relay.close()
	bare.close()
	return nil
}

// TestTheConsoleRelayShutsItsConhostToTheAccount is the wiring half of the
// P0-1 fix. internal/win/proc's
// TestAConsoleHostShutToItsAccountIsClosedToARestrictedToken measures that
// ShieldConhost shuts what it is handed, from a restricted token's seat, and
// internal/e2e's admin-gated test measures the whole account -> stub ->
// program chain end to end. Neither can see the seam this test holds: that
// takeConsoleRelay, on every call, picks the one host its own
// CreatePseudoConsole created out of whatever conhosts this process already
// has, and hands it to ShieldConhost before the relay is handed back.
//
// The seat is the fixture account's, built in account_test.go: this binary is
// started as a dedicated local account with RunAsAccount -- the launch a real
// run gives its stub -- and the choreography runs in that child. The old seat
// was this process's own token, the runner's identity on CI -- the built-in
// Administrator, SID ending -500 -- and there the shut's deliberate
// administrators allow answered every door, because Shield's list refuses the
// account's own SID first and keeps that allow only after it; the test had to
// split into a refusal branch and a protected-bit branch to say anything at
// all from such a seat. The account's seat needs no split: the refusals are
// the direct measurement everywhere the test runs. The elevated branch is
// gone with the seat that needed it; what it read -- the list's protected
// bit -- is the one thing Shielded reads for the same reason, and the tests
// in this package that read Shielded still cover it.
//
// The controls come first, and their order is load-bearing. The walk is
// settled before any list is taken, because the fixture child is born by
// RunAsAccount with CREATE_NO_WINDOW and so has a birth console host of its
// own that arrives in ConsoleHostChildren's walk late. The seat itself
// arrives already shut to the account: RunAsAccount applies the same
// deny-first list Shield applies from inside to the stub's process before its
// first instruction (internal/win/proc's narrowBeforeResume), so this
// process's own open for PROCESS_ALL_ACCESS must be refused, and the refusal
// is part of the seat -- pinned so a launch that stops narrowing its stubs is
// caught rather than silently measured from. The question of whether this
// seat can open anything at all is answered instead by the birth console's
// host -- the one console host the walk can name, spawned by the launch
// itself with the account's ordinary list -- which must open for
// PROCESS_ALL_ACCESS. The last control stands up a bare pty's conhost and
// opens it for PROCESS_ALL_ACCESS -- the exact door the review measured open
// on an unshielded host -- and it must succeed too: if it is already shut,
// nothing below is measuring the fix.
//
// The bare pty's conhost is then left alive on purpose, through the relay's
// creation and the door measurements both. That is a small measure in
// itself: the diff that names the relay's host is a before/after set
// difference taken inside takeConsoleRelay -- the before-list at its top,
// the after-list in shutNewConsoleHost -- so a host present in both of ITS
// snapshots cancels out of the diff, whatever it is. A conhost already
// standing while the call runs must not satisfy the wiring, and must not
// confuse it either.
func TestTheConsoleRelayShutsItsConhostToTheAccount(t *testing.T) {
	requireAdministrator(t)
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	a := aShutAccount(t, "shld0dea0011")
	_, work, exe := fixtureTree(t, a)
	a.runFixture(t, exe, work, relayFixtureFlag)
}
