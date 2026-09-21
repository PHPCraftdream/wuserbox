// The console-host shut measured from the seat the wiring is answerable to:
// this process's own token, the account's ordinary one -- the very token
// takeConsoleRelay creates the relay's host under. What the production code
// promises is not only that ShieldConhost shuts a host it is handed
// (internal/win/proc measures that from a restricted token's seat) but that
// takeConsoleRelay finds the one host its own CreatePseudoConsole made and
// hands it over before the relay is handed back. That seam is what this file
// holds to the doors the review's P0-1 measured open.

package exec

import (
	"errors"
	"os"
	"slices"
	"syscall"
	"testing"
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

	// The read of the host's permission list itself, which is the elevated
	// branch's measurement: GetSecurityInfo hands back the descriptor,
	// GetSecurityDescriptorControl its control bits, and the bit this test
	// asks of them is the same one Shielded reads, for the same reason.
	procGetSecurityInfoInExec              = w32.Advapi32.NewProc("GetSecurityInfo")
	procGetSecurityDescriptorControlInExec = w32.Advapi32.NewProc("GetSecurityDescriptorControl")
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

	// The read of the host's permission list itself, for the seat the
	// refusals cannot be asked of: READ_CONTROL to open the shut host with,
	// SE_KERNEL_OBJECT and DACL_SECURITY_INFORMATION to name the list to
	// GetSecurityInfo, and SE_DACL_PROTECTED, the control bit that says the
	// list is protected -- the one answer no seat, however elevated, can
	// talk its way past.
	readControl                   = 0x00020000 // READ_CONTROL
	seKernelObjectInExec          = 6          // SE_KERNEL_OBJECT
	daclSecurityInformationInExec = 0x4        // DACL_SECURITY_INFORMATION
	seDaclProtectedInExec         = 0x1000     // SE_DACL_PROTECTED

	invalidHandle = ^uintptr(0)
)

// aBarePtyConhost gives this process a console host of its own, the same
// shape internal/win/proc/conhost_test.go's aConhostOfOurOwn stands one up
// in: ConsoleHostChildren's before-list, two pipe pairs, CreatePseudoConsole
// with the packed 80x25 COORD the package's own coordValue produces -- the
// same packing expression takeConsoleRelay hands it, so test and production
// cannot drift -- and the test's own copies of the input-read and
// output-write ends closed the moment the call returns, which duplicates what
// it needs. Exactly one new pid is tolerated: anything else means the walk
// cannot tell this test's host from a stranger's, and nothing measured
// against a wrong pid would mean anything.
//
// Nothing is ever attached to the console, so the output drain sits idle; it
// exists so a host that did write could never block on a full pipe. The host
// is left alive when the helper returns -- the caller decides when its
// console ends -- and the cleanup closes the pseudo console only if the host
// is still a conhost child of this process: a handle value whose object has
// been closed and handed back by the table must not be shown to
// ClosePseudoConsole a second time, and the walk by parentage and name, the
// same walk ConsoleHostChildren exists for, is what says the close is still
// ours to make. A walk that errors says nothing either way, and there the
// ordinary case is a host still to shut.
func aBarePtyConhost(t *testing.T) (syscall.Handle, uint32) {
	t.Helper()
	before, err := proc.ConsoleHostChildren(uint32(syscall.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	ptyInRead, ptyInWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ptyOutRead, ptyOutWrite, err := os.Pipe()
	if err != nil {
		ptyInRead.Close()
		ptyInWrite.Close()
		t.Fatal(err)
	}
	var hpc syscall.Handle
	r, _, callErr := procCreatePseudoConsole.Call(coordValue(80, 25), ptyInRead.Fd(), ptyOutWrite.Fd(), 0,
		uintptr(unsafe.Pointer(&hpc)))
	ptyInRead.Close()
	ptyOutWrite.Close()
	if r != 0 {
		ptyInWrite.Close()
		ptyOutRead.Close()
		t.Fatalf("CreatePseudoConsole: hresult 0x%x (%v)", r, callErr)
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
		t.Fatal(err)
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
		t.Fatalf("creating a bare pseudo console did not leave exactly one new console host: before %v, after %v",
			before, after)
	}
	pid := fresh[0]
	t.Cleanup(func() {
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
		ptyInWrite.Close()
		ptyOutRead.Close()
	})
	return hpc, pid
}

// canOpen answers the one question an access mask asks: could this process's
// own token open pid for access? A nonzero handle is yes, and is closed at
// once; zero is no. There is no error channel -- the bool is the whole
// answer, because the difference between "refused" and "refused for a
// stranger reason" is not a distinction this test acts on.
func canOpen(t *testing.T, pid uint32, access uintptr) bool {
	t.Helper()
	handle, _, _ := procOpenProcessInExec.Call(access, 0, uintptr(pid))
	if handle == 0 {
		return false
	}
	syscall.CloseHandle(syscall.Handle(handle))
	return true
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
// The controls come first, and their order is load-bearing. The first control
// opens this test process itself for PROCESS_ALL_ACCESS by pid: the refusals
// measured below would mean nothing if this process could not open anything
// at all, and its own process object is unshielded and its own account's, so
// the open must succeed. The second control stands up a bare pty's conhost
// and opens it for PROCESS_ALL_ACCESS -- the exact door the review measured
// open on an unshielded host -- and it must succeed too: if it is already
// shut, nothing below is measuring the fix.
//
// The bare pty's conhost is then left alive on purpose, cleanup and all,
// through the relay's creation. That is a small measure in itself: the diff
// that names the relay's host is a before/after set difference taken inside
// takeConsoleRelay -- the before-list at its top, the after-list in
// shutNewConsoleHost -- so a host present in both of ITS snapshots cancels
// out of the diff, whatever it is. A conhost already standing while the call
// runs must not satisfy the wiring, and must not confuse it either.
func TestTheConsoleRelayShutsItsConhostToTheAccount(t *testing.T) {
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	ownPid := uint32(syscall.Getpid())

	// CONTROL, and first: this process can open something at all.
	if !canOpen(t, ownPid, processAllAccess) {
		t.Fatal("this process could not open its own process object for everything, " +
			"so the refusals measured below would mean nothing")
	}

	// CONTROL: the door the review measured open on an unshielded host.
	_, barePid := aBarePtyConhost(t)
	if !canOpen(t, barePid, processAllAccess) {
		t.Fatalf("an unshielded console host (%d) already refuses this account everything, "+
			"so nothing below is measuring the fix", barePid)
	}

	relayBefore, err := proc.ConsoleHostChildren(ownPid)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := takeConsoleRelay()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.close()
	relayAfter, err := proc.ConsoleHostChildren(ownPid)
	if err != nil {
		t.Fatal(err)
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
		t.Fatalf("takeConsoleRelay did not leave exactly one new console host: before %v, after %v, "+
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
	//
	// The seat is this process's own token, the account's ordinary one --
	// the same account the host runs as and the token it was born under.
	// The shut keeps the administrators an allow entry on purpose, so a run
	// seated in an elevated token would still open these doors through it.
	// Which of the two seats this process holds decides what is measured
	// below: the refusals, from the ordinary desk's seat; the protected
	// bit, from an elevated one, where the allow entry answers every door.
	if !token.IsAdmin() {
		// This branch is the ordinary desk's seat, where the refusals are
		// the direct measurement.
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
			if canOpen(t, hostPid, door.access) {
				t.Errorf("the console host takeConsoleRelay created (%d) let this account in for %s; "+
					"the shut was meant to close that door", hostPid, door.name)
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
			t.Fatalf("listing the threads of console host %d: %v", hostPid, callErr)
		}
		defer syscall.CloseHandle(syscall.Handle(snapshot))
		entry := make([]byte, threadEntrySize)
		*(*uint32)(unsafe.Pointer(&entry[0])) = threadEntrySize
		var tid uint32
		for step := procThread32FirstInExec; ; step = procThread32NextInExec {
			r, _, listErr := step.Call(snapshot, uintptr(unsafe.Pointer(&entry[0])))
			if r == 0 {
				if errors.Is(listErr, syscall.Errno(errNoMoreItems)) {
					break
				}
				t.Fatalf("walking the threads of console host %d: %v", hostPid, listErr)
			}
			if *(*uint32)(unsafe.Pointer(&entry[ownerProcessOffset])) != hostPid {
				continue
			}
			tid = *(*uint32)(unsafe.Pointer(&entry[threadIDOffset]))
			break
		}
		if tid == 0 {
			t.Fatalf("no thread of console host %d was found; a running process has threads, "+
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
				t.Errorf("a thread of the console host (%d) was open for %s; "+
					"redirecting or rewriting a thread is running code in the host", hostPid, door.name)
			}
		}
	} else {
		// The elevated seat cannot be asked the refusals: the allow entry the
		// shut keeps for the administrators -- so the machine can still end a
		// runaway console -- answers every door above with yes, by design, and
		// an open measured through a deliberate allow is no measurement at all.
		// What does not depend on the seat is the one thing Shielded reads for
		// the same reason: whether the host's permission list is protected.
		// Windows hands a process its token's default list, unprotected;
		// nothing, not even elevation, leaves a list protected unless something
		// set it so -- and in a run only the shut sets it. CI, which runs these
		// tests elevated, exercises this branch.
		//
		// Positive control first: the elevated seat must be able to open the
		// host at all, or the read below means nothing.
		if !canOpen(t, hostPid, readControl) {
			t.Fatalf("the elevated seat could not open console host %d even for READ_CONTROL, "+
				"so the protected-bit check below would mean nothing", hostPid)
		}
		handle, _, openErr := procOpenProcessInExec.Call(readControl, 0, uintptr(hostPid))
		if handle == 0 {
			t.Fatalf("opening console host %d to read its permission list: %v", hostPid, openErr)
		}
		defer syscall.CloseHandle(syscall.Handle(handle))
		var dacl, descriptor uintptr
		if r, _, listErr := procGetSecurityInfoInExec.Call(handle, seKernelObjectInExec,
			daclSecurityInformationInExec, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
			uintptr(unsafe.Pointer(&descriptor))); r != 0 {
			t.Fatalf("reading the permission list of console host %d: error %d (%v)",
				hostPid, r, listErr)
		}
		defer w32.Free(descriptor)
		var control uint16
		var revision uint32
		if r, _, callErr := procGetSecurityDescriptorControlInExec.Call(descriptor,
			uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision))); r == 0 {
			t.Fatalf("reading the control bits of console host %d's descriptor: %v",
				hostPid, callErr)
		}
		if control&seDaclProtectedInExec == 0 {
			t.Errorf("the relay's console host sits on an unprotected permission list")
		}
	}
	// The relay is closed by the defer above, which ends its host; the bare
	// pty's console is ended by its own cleanup, which checks that the host
	// it closes is still this process's before closing it.

	// What this does NOT measure: the doors as a restricted token of the
	// same account sees them, which is internal/win/proc's
	// TestAConsoleHostShutToItsAccountIsClosedToARestrictedToken, and the
	// real account -> stub -> program chain across processes, which is
	// internal/e2e's admin-gated
	// TestEveryConsoleHostOfARunIsClosedToTheSandboxedProgram. This test's
	// question is narrower and different: that the wiring applies the shut
	// to the host the relay creates, on every call, before the relay is
	// handed back.
}
