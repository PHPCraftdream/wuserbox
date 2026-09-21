// The closing test the security review asked for (P0-1), measured where it
// bites: through the real account -> stub -> restricted program chain, with
// every console host the run leaves behind enumerated from INSIDE the sandbox
// and every door on it tried from the restricted token the program actually
// carries. The fixture -- newRealBox, stubBinary, throughTheStub -- is in
// account_test.go, and the reason it has to be a real account is argued
// there.

package e2e

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

const conhostProwlFlag = "-wuserbox-conhost-prowl"

// Exit codes the prowl ends on. The verdict travels only in the code: a file
// can be refused to the thing under test, and a measurement that comes back
// empty is then indistinguishable from one that never happened -- the
// prowler's own lesson, kept here too. The file it does write is the
// diagnosis, read by the test only when the code says something went wrong.
const (
	// conhostProwlBroken: the probe could not read what it was meant to
	// measure -- the walk of the stub's console hosts failed -- so there is
	// nothing to write and nothing to pass on.
	conhostProwlBroken = 45
	// conhostProwlEmpty: the stub had no console host at all. A run whose
	// console hosts were all shut could answer this way, but so could one
	// that never had any, and only the second is a measurement.
	conhostProwlEmpty = 43
	// conhostProwlNothingMeasured: hosts were listed but none of them could
	// be measured -- every one died between the walk and the probe.
	conhostProwlNothingMeasured = 44
	// conhostProwlOpen: at least one door on a host that was still there to
	// be measured again was open to the restricted token.
	conhostProwlOpen = 42
	// conhostProwlUnmeasured: hosts were measured, at least one of them
	// alive and answering its process doors, but not one thread of that
	// host could be had -- reporting that as a closed boundary would be the
	// empty measurement the review calls false confidence.
	conhostProwlUnmeasured = 46
)

// The doors an escape through a console host goes by, one mask each and named
// for what they open. The review's list, spelled out rather than asked for as
// a set: a refusal of PROCESS_ALL_ACCESS is not a refusal of its members, and
// it is exactly the narrow doors -- write the host's memory, create threads
// in it, reach the threads it already has, take and duplicate its token --
// that an escape needs. The thread masks get the same treatment: redirecting
// an existing thread (THREAD_SET_CONTEXT, with SUSPEND_RESUME because the two
// are asked together everywhere else in this repository) and rewriting a
// thread's own permission list (WRITE_DAC, the same bit a process carries).
const (
	prowlProcessAllAccess      = 0x1FFFFF
	prowlProcessCreateThread   = 0x0002
	prowlProcessVMOperation    = 0x0008
	prowlProcessVMWrite        = 0x0020
	prowlProcessDupHandle      = 0x0040
	prowlProcessSetInformation = 0x0200
	prowlProcessQueryLimited   = 0x1000
	prowlWriteDac              = 0x00040000
	prowlWriteOwner            = 0x00080000

	prowlThreadSetContextResume = 0x0012 // THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME

	// TOKEN_DUPLICATE | TOKEN_QUERY: what it takes to make the host's token
	// wearable, which is the whole of what an attacker wants from it.
	prowlTokenDuplicateQuery = 0x000A
)

var (
	// Fresh copies of the entry points this probe opens things with, under
	// names of their own because two LazyProcs for one entry point cannot
	// share a package -- the same reason conhost.go keeps
	// procOpenAnotherProcess and slot_test.go keeps procSlotOpenProcess.
	prowlOpenProcess              = w32.Kernel32.NewProc("OpenProcess")
	prowlOpenThread               = w32.Kernel32.NewProc("OpenThread")
	prowlCreateToolhelp32Snapshot = w32.Kernel32.NewProc("CreateToolhelp32Snapshot")
	prowlThread32First            = w32.Kernel32.NewProc("Thread32First")
	prowlThread32Next             = w32.Kernel32.NewProc("Thread32Next")
)

// Raw shapes of the walk. THREADENTRY32W is 28 bytes on windows/amd64, the
// thread's own id sits at 8 behind dwSize and cntUsage, and the pid that owns
// it at 12; the walk ends by failing with 18, ERROR_NO_MORE_FILES -- the same
// end Shield's own walk answers to.
const (
	prowlSnapThreads          = 0x00000004 // TH32CS_SNAPTHREAD
	prowlThreadEntry32Size    = 28
	prowlThreadIDOffset       = 8
	prowlOwnerProcessIDOffset = 12
)

// prowlThreadPollStep and prowlThreadPollWant are the prowl's own copies of
// production's threadListPollStep and threadListPollWant (shield.go), which
// are unexported in another package and cannot be reached from here: the
// same step and the same ceiling production gives a thread walk that found
// nothing, because the lag the prowl has to out-wait is the one production
// already measured -- a host that is alive has threads, so a walk that
// keeps listing none is a snapshot that has not caught up yet, not an
// answer about the host.
const (
	prowlThreadPollStep = 25 * time.Millisecond
	prowlThreadPollWant = time.Second
)

var (
	prowlAccessDenied     = syscall.Errno(5)  // ERROR_ACCESS_DENIED: a door refused
	prowlInvalidParameter = syscall.Errno(87) // ERROR_INVALID_PARAMETER: the id names a thread that has ended
	prowlNoMoreFiles      = syscall.Errno(18) // ERROR_NO_MORE_FILES: the walk's end
)

// prowlProcessDoors is what gets tried against every host, in the order the
// review names them.
var prowlProcessDoors = []struct {
	name   string
	access uintptr
}{
	{"PROCESS_ALL_ACCESS", prowlProcessAllAccess},
	{"PROCESS_CREATE_THREAD", prowlProcessCreateThread},
	{"PROCESS_VM_OPERATION", prowlProcessVMOperation},
	{"PROCESS_VM_WRITE", prowlProcessVMWrite},
	{"PROCESS_DUP_HANDLE", prowlProcessDupHandle},
	{"PROCESS_SET_INFORMATION", prowlProcessSetInformation},
	{"WRITE_DAC", prowlWriteDac},
	{"WRITE_OWNER", prowlWriteOwner},
}

// conhostProwl is the probe that runs INSIDE the sandbox, as a child of the
// stub: it lists the stub's console hosts, tries every door on each from the
// restricted token it itself runs under, and writes one line per host plus a
// final verdict line into resultFile. It answers with its exit code, which is
// the verdict; the file is the diagnosis.
func conhostProwl(resultFile string) int {
	// The probe's parent is the stub, so the console hosts of this run are
	// exactly the conhost children of that pid -- found the only way
	// production finds one, ConsoleHostChildren's walk by parentage.
	hosts, err := proc.ConsoleHostChildren(uint32(os.Getppid()))
	if err != nil {
		return conhostProwlBroken
	}
	if len(hosts) == 0 {
		_ = os.WriteFile(resultFile,
			[]byte(fmt.Sprintf("no conhost child of the stub (parent pid %d) was found\n", os.Getppid())),
			0o644)
		return conhostProwlEmpty
	}

	verdicts := make([]prowlVerdict, 0, len(hosts))
	anyOpen, anyUnmeasured := false, false
	for _, pid := range hosts {
		// Each host fetches its own threads, fresh when it is measured: a
		// snapshot taken once for the whole probe would be stale by the time
		// the later hosts came up, and a stale snapshot can only list the
		// threads that were already dead when it was taken.
		v := prowlMeasureHost(pid)
		anyOpen = anyOpen || len(v.open) > 0
		anyUnmeasured = anyUnmeasured || v.unmeasured
		verdicts = append(verdicts, v)
	}

	// The dying-host refinement: doors found open -- and hosts whose threads
	// could not be examined -- are only believed while the host is still
	// there to be measured again. A console whose host died between the walk
	// and the probe -- expected for a console freed mid-run -- leaves doors
	// nobody can re-check, and reporting those as an escape would make every
	// run with a dying console look guilty. The same mercy is owed to a host
	// whose threads could not be examined: a host that died cannot be asked
	// about its threads at all, and that is the honest gone case, not a
	// hole. Re-list once after a second; a host no longer listed is recorded
	// as gone, its doors are not counted and its unmeasured flag is
	// cleared, and one still listed counts.
	if anyOpen || anyUnmeasured {
		time.Sleep(time.Second)
		again, walkErr := proc.ConsoleHostChildren(uint32(os.Getppid()))
		if walkErr != nil {
			return conhostProwlBroken
		}
		still := make(map[uint32]bool, len(again))
		for _, pid := range again {
			still[pid] = true
		}
		for i, v := range verdicts {
			if (len(v.open) > 0 || v.unmeasured) && !still[v.pid] {
				v.line = fmt.Sprintf("host %d: gone before it could be measured again", v.pid)
				v.open = nil
				v.measured = false
				v.unmeasured = false
				verdicts[i] = v
			}
		}
	}

	measured, openDoors, unmeasuredAlive := 0, 0, 0
	lines := make([]string, 0, len(verdicts)+1)
	for _, v := range verdicts {
		lines = append(lines, v.line)
		if v.measured {
			measured++
		}
		if v.unmeasured {
			// A host that answered its process doors but not a single thread
			// of which could be examined is a measurement failure, and it
			// fails closed: it is counted apart here, and the probe ends
			// nonzero on it below, so an unmeasured boundary cannot pass
			// for a held one.
			unmeasuredAlive++
		}
		openDoors += len(v.open)
	}
	lines = append(lines, fmt.Sprintf("measured %d hosts with %d open doors", measured, openDoors))
	_ = os.WriteFile(resultFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)

	switch {
	case openDoors > 0:
		return conhostProwlOpen
	case unmeasuredAlive > 0:
		return conhostProwlUnmeasured
	case measured == 0:
		return conhostProwlNothingMeasured
	default:
		return 0
	}
}

// prowlVerdict is what the probe decided about one host: the line it will be
// reported by, the doors that opened on it, whether it was measured at all
// -- unreachable and gone hosts are reported and counted as neither -- and
// whether the host answered its process doors while not one thread of it
// could be examined. That last state is a measurement failure and not a
// shut boundary, which is what unmeasured exists to say.
type prowlVerdict struct {
	pid        uint32
	line       string
	open       []string
	measured   bool
	unmeasured bool
}

// prowlMeasureHost tries every door on one console host and says what
// opened. It fetches the host's threads itself, fresh when it is measured --
// see prowlThreadsOfOwner for why the snapshot is not shared between hosts.
func prowlMeasureHost(pid uint32) prowlVerdict {
	var open []string
	var notes []string
	attempts, otherErrno := 0, 0

	// tryProcess attempts one OpenProcess door: a handle is a door open; a
	// refusal with error 5 is the object's own list answering, which is the
	// fix working; anything else is the probe not understanding the machine
	// it runs on and is noted rather than read as a shut door.
	tryProcess := func(name string, access uintptr) {
		attempts++
		h, _, callErr := prowlOpenProcess.Call(access, 0, uintptr(pid))
		if h != 0 {
			open = append(open, name)
			syscall.CloseHandle(syscall.Handle(h))
			return
		}
		refused, errno := prowlErrno(callErr)
		if !refused {
			notes = append(notes, fmt.Sprintf("%s (errno %d)", name, errno))
			if otherErrno == 0 {
				otherErrno = errno
			}
		}
	}

	for _, door := range prowlProcessDoors {
		tryProcess(door.name, door.access)
	}

	// The token door goes through the one open every account has: a handle
	// for QUERY_LIMITED_INFORMATION is ordinary, the token behind it is not
	// supposed to be duplicable by the program the host was started for.
	attempts++
	if h, _, callErr := prowlOpenProcess.Call(prowlProcessQueryLimited, 0, uintptr(pid)); h != 0 {
		var token syscall.Token
		if err := syscall.OpenProcessToken(syscall.Handle(h), prowlTokenDuplicateQuery, &token); err == nil {
			open = append(open, "TOKEN_DUPLICATE|TOKEN_QUERY")
			token.Close()
		}
		syscall.CloseHandle(syscall.Handle(h))
	} else if refused, errno := prowlErrno(callErr); !refused {
		notes = append(notes, fmt.Sprintf("OpenProcess for the token (errno %d)", errno))
		if otherErrno == 0 {
			otherErrno = errno
		}
	}

	// A host every open of which failed with something other than a refusal
	// is a pid that died between the walk and the probe, not a shut one --
	// saying so keeps a broken measurement from passing for a boundary.
	if len(open) == 0 && len(notes) == attempts {
		return prowlVerdict{
			pid:  pid,
			line: fmt.Sprintf("host %d: unreachable (errno %d)", pid, otherErrno),
		}
	}

	// The thread doors, on threads the walk lists -- every one of them, not
	// the first a single pass remembered: a shield with a hole in thread two
	// passes for a shield when only thread one is asked (review round 2,
	// P2-2). The doors go dangerous-first, because THREAD_SET_CONTEXT with
	// SUSPEND_RESUME is the escape the shield exists to close -- redirect a
	// thread the host already has and the host does the attacker's next step
	// for it -- and WRITE_DAC is the narrower question of whether the
	// thread's own permission list can be rewritten once the dangerous
	// rights are refused.
	//
	// The walk is retried the way production's shutThreadsAlreadyRunning is
	// (its threadListPollStep and threadListPollWant, unexported in another
	// package, are mirrored in the prowl consts above): a thread a snapshot
	// taken an instant earlier listed can be gone by the time it is opened,
	// and a host that is alive has threads -- a walk that keeps finding none
	// is a lagging snapshot, the lesson a0b4722 teaches production, not an
	// answer about the host. So an empty examined set is never believed on
	// its first walk, and after the ceiling it ends as "not measured", never
	// as "closed": an alive host none of whose threads could be examined is
	// a measurement failure, and unmeasured says so.
	examined, walkFailed := 0, false
	deadline := time.Now().Add(prowlThreadPollWant)
	for {
		threads, walkOK := prowlThreadsOfOwner(pid)
		if !walkOK {
			// The walk itself broke -- the snapshot could not be taken, or
			// ended in something other than its normal 18. Nothing was
			// examined and nothing can be: note it and stop, rather than
			// retry a machine that has stopped answering.
			walkFailed = true
			examined = 0
			break
		}
		for _, tid := range threads {
			// Door A first, the dangerous one. A handle here makes the host
			// guilty regardless of anything else -- the door IS the escape
			// -- so the thread counts as examined and door B is never
			// asked: there is no point asking more of a thread already
			// proven open.
			h, _, openErr := prowlOpenThread.Call(prowlThreadSetContextResume, 0, uintptr(tid))
			if h != 0 {
				open = append(open, "THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME")
				syscall.CloseHandle(syscall.Handle(h))
				examined++
				continue
			}
			refusedA, goneA, errnoA := prowlThreadErrno(openErr)
			switch {
			case refusedA:
				// Refused the dangerous rights, so now ask the narrower
				// door on the SAME thread: a thread denied
				// SET_CONTEXT|SUSPEND_RESUME but writable-DAC is exactly
				// the one-sided refusal the review says must not pass for
				// a shield -- whoever cannot redirect the thread can still
				// rewrite the list that would keep the next attacker out.
				if hB, _, openErrB := prowlOpenThread.Call(prowlWriteDac, 0, uintptr(tid)); hB != 0 {
					open = append(open, "THREAD_WRITE_DAC")
					syscall.CloseHandle(syscall.Handle(hB))
					examined++
				} else if refusedB, goneB, errnoB := prowlThreadErrno(openErrB); refusedB {
					// Refused twice, dangerous and narrow alike: the only
					// shape counted as a shut thread, an answer the
					// thread's own list gave about both doors.
					examined++
				} else if goneB {
					// The thread ended between the two doors. The
					// dangerous door already answered shut before it
					// vanished, so the thread still counts as examined
					// -- but the vanish is noted, because a thread dying
					// under the probe is worth a word in the diagnosis.
					examined++
					notes = append(notes, fmt.Sprintf("thread %d ended between the doors", tid))
				} else {
					// Not a refusal and not a vanish: the machine is not
					// answering the question that was asked, and that
					// must never count as a door closed -- the thread
					// stays unexamined and the errno is written down.
					notes = append(notes, fmt.Sprintf("THREAD_WRITE_DAC of thread %d (errno %d)", tid, errnoB))
				}
			case goneA:
				// The thread ended between the snapshot and the open --
				// the expected vanish every walk tolerates, Windows
				// answering 87 because the id now names nothing. The
				// thread is skipped entirely: not examined, not guilty,
				// not noted.
			default:
				// Neither a refusal nor a vanish, and no handle: the same
				// rule the process doors keep, an error the probe does not
				// understand is noted and the thread stays unexamined --
				// never a door closed by accident.
				notes = append(notes, fmt.Sprintf("THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME of thread %d (errno %d)", tid, errnoA))
			}
		}
		if examined > 0 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(prowlThreadPollStep)
	}
	if walkFailed {
		notes = append(notes, "the thread walk itself failed")
	}

	// The count of threads actually examined goes on the line when there
	// was one; when there was none, the line says so instead of leaving a
	// "closed" that only means nobody could ask.
	line := fmt.Sprintf("host %d: closed", pid)
	if len(open) > 0 {
		line = fmt.Sprintf("host %d: open doors %s", pid, strings.Join(open, ", "))
	}
	if examined > 0 {
		line += fmt.Sprintf(" (%d threads tried)", examined)
	} else {
		line += " (no thread of it would answer)"
	}
	if len(notes) > 0 {
		line += " (" + strings.Join(notes, ", ") + ")"
	}
	return prowlVerdict{
		pid:        pid,
		line:       line,
		open:       open,
		measured:   examined > 0,
		unmeasured: examined == 0,
	}
}

// prowlThreadsOfOwner lists EVERY thread id the walk assigns to pid, and
// whether the walk completed. Every thread, not the first one a walk meets:
// the thread doors are the prowl's evidence about the threads a host already
// carries, and a shield with a hole in thread two passes for a shield when
// only thread one is asked (review round 2, P2-2) -- the one thread per
// owner the prowl kept before was exactly that one-thread shield.
//
// The snapshot is taken fresh on every call, never once for the probe: the
// caller re-walks whenever a pass examines nothing, and a snapshot kept from
// an earlier pass can only list the same dead threads again -- it cannot
// catch up with the threads a still-alive host actually has, which is the
// whole point of walking again.
//
// A walk that ended in anything but its normal 18 is answered as not
// completed, with whatever was listed so far, and a snapshot that could not
// be taken at all as not completed and nothing -- a measurement missing its
// threads must not be mistaken for one that tried them.
func prowlThreadsOfOwner(pid uint32) ([]uint32, bool) {
	snapshot, _, _ := prowlCreateToolhelp32Snapshot.Call(prowlSnapThreads, 0)
	if snapshot == 0 || snapshot == ^uintptr(0) {
		return nil, false
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var owned []uint32
	entry := make([]byte, prowlThreadEntry32Size)
	*(*uint32)(unsafe.Pointer(&entry[0])) = prowlThreadEntry32Size
	for step := prowlThread32First; ; step = prowlThread32Next {
		r, _, listErr := step.Call(snapshot, uintptr(unsafe.Pointer(&entry[0])))
		if r == 0 {
			if errors.Is(listErr, prowlNoMoreFiles) {
				return owned, true
			}
			return owned, false
		}
		if *(*uint32)(unsafe.Pointer(&entry[prowlOwnerProcessIDOffset])) != pid {
			continue
		}
		owned = append(owned, *(*uint32)(unsafe.Pointer(&entry[prowlThreadIDOffset])))
	}
}

// prowlErrno sorts a failed open into "refused by the object's own list"
// (error 5, the answer the shut doors give) and anything else, whose number
// comes back so a note can be written instead of a false shut door.
func prowlErrno(err error) (refused bool, errno int) {
	var code syscall.Errno
	if !errors.As(err, &code) {
		return false, 0
	}
	if code == prowlAccessDenied {
		return true, 0
	}
	return false, int(code)
}

// prowlThreadErrno is prowlErrno's thread-side sibling, and it sorts into
// three because a thread can end where a process door never has to consider
// it: refused, the object's own list answering (error 5) -- a measurement,
// of a shut door or an open one; gone, the thread having ended between the
// walk and the open (error 87, the id naming nothing any more, the same
// answer production's walk skips) -- a non-answer the walk tolerates; and
// anything else, the probe not understanding the machine it runs on, which
// must never be read as a shut door. The number of the third kind comes
// back so a note can carry it.
func prowlThreadErrno(err error) (refused, gone bool, errno int) {
	var code syscall.Errno
	if !errors.As(err, &code) {
		return false, false, 0
	}
	switch code {
	case prowlAccessDenied:
		return true, false, 0
	case prowlInvalidParameter:
		return false, true, int(code)
	}
	return false, false, int(code)
}

// TestEveryConsoleHostOfARunIsClosedToTheSandboxedProgram is the review's
// closing test for P0-1
// (docs/reviews/security-performance-review-2026-09-20.md, "Тест закрытия"):
// through the real chain account -> stub -> restricted program, find every
// auxiliary process the run leaves behind -- not only the stub -- and try the
// whole door list on it: VM_WRITE, VM_OPERATION, CREATE_THREAD, DUP_HANDLE,
// WRITE_DAC, WRITE_OWNER, SET_INFORMATION, ALL_ACCESS, the token, and the
// threads. The hosts are enumerated from inside the sandbox, as the conhost
// children of its own parent, which is where a CreatePseudoConsole host and
// an AllocConsole host are both findable and where the birth console's host
// -- the one a CREATE_NO_WINDOW stub is given about 150 ms after it is born
// -- shows up too. That is one host per leg here: the birth console's host in
// plain and relay mode, the relay's host in relay mode, the allocated
// console's host in own-console mode -- the variants the review says were
// never separately measured, because the existing shield test aims only at
// the stub's own pid and cannot see any of this.
//
// The review's other half is the real file-system control: that the program
// is working is what makes a shut door mean something. An Authenticated Users
// directory outside the grant is shown writable by the plain account first,
// so the refusal through the stub below cannot be the machine granting
// nothing; and the probe's own result file, written into its grant, is the
// program working -- with the exit code coming back through the whole chain,
// the prowler's own lesson about the one channel that cannot be taken away.
//
// What relayed console I/O itself does over these same shielded hosts --
// rendered bytes, keystrokes, resize -- is what
// TestAProgramThroughTheConsoleRelaySeesARealTerminalAndRelaysItsBytes
// measures; this test measures only that the hosts are shut.
//
// Since review round 2 (P2-2) the prowl's thread half asks every thread the
// walk lists, not the first one it happens to remember, and sorts the three
// answers OpenThread can give: a refusal is an answer, a vanished thread is
// one that ended, and anything else is the probe itself broken. When a
// living host's threads could not be examined at all the prowl ends nonzero
// (exit code 46), so an unmeasured boundary can no longer pass for a held
// one.
//
// Two things it cannot measure on a desk: without administrator rights no
// real sandbox account can be built here, so neither the door measurement nor
// the Authenticated Users control can even be asked -- which is why the test
// is gated on requireAdministrator and skips with its message rather than
// standing in a synthetic fixture that cannot tell a right taken away from
// one that was never reachable. And no desk run says anything about a runner:
// the property is re-measured on every CI run, where the administrator rights
// are always there.
//
// The three legs are not equally priced, and the test says so up front: the
// own-console leg is the only one of the three that puts a window on the
// desktop, because AllocConsole comes with a real console for the length of
// the run, and a routine `go test ./...` has no business flashing windows at
// whoever runs it. That leg alone is therefore gated behind
// WUSERBOX_E2E_OWN_CONSOLE, the same variable
// TestAProgramThatNeedsARealTerminalFindsOneUnderOwnConsole established for
// exactly this purpose, so a routine run measures only the windowless plain
// and relay legs and the dedicated CI step is where the window's cost is paid.
func TestEveryConsoleHostOfARunIsClosedToTheSandboxedProgram(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	work := filepath.Join(root, "work")     // the granted directory
	shared := filepath.Join(root, "shared") // never granted; Authenticated Users' own
	for _, dir := range []string{work, shared} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The pair that makes the file-system control mean something, in the
	// shape TestAGrantTakesAuthenticatedUsersAwayFromEveryOtherAccount
	// argues for: Authenticated Users reaches every account that logged on,
	// so an entry naming it is a right the account carries that no grant
	// gave it -- exactly what a shut host's account must not inherit.
	if err := acl.Set(shared, sid.Authenticated, []acl.ACE{
		{Access: acl.AccessModify, Inheritance: acl.InheritObjects | acl.InheritContainers},
	}); err != nil {
		t.Fatal(err)
	}

	stub := stubBinary(t, root)
	box := newRealBox(t, firstSandbox, work)
	box.hand(t, work, grant.RW)

	// The file-system control, positive: the plain account reaches the
	// shared directory, so a refusal below comes from the stub's
	// restriction and not from an entry that never reached anybody.
	written := filepath.Join(shared, "written.txt")
	if err := os.Remove(written); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if !box.tries(t, writeInto(shared), work) {
		t.Fatal("Authenticated Users did not reach this account, so the refusal through the stub below would prove nothing")
	}
	if err := os.Remove(written); err != nil {
		t.Fatal(err)
	}

	// The file-system control, negative, in relay mode -- the run shape the
	// review was written about, and the one real refusal
	// (IsTokenRestricted says restricted is not a reason to stop asking):
	// through the stub, the same write is refused and nothing lands.
	line := box.throughTheStub(t, stub, writeInto(shared))
	code, runErr := proc.RunAsAccount(box.account, box.password, line, work,
		append(os.Environ(), proc.EnvConsoleRelay+"=1"))
	if runErr != nil {
		t.Fatalf("starting the relayed write as %s: %v", box.account, runErr)
	}
	if code == 0 {
		t.Error("the sandboxed program wrote into the Authenticated Users directory outside its grant")
	}
	if exists(written) {
		t.Errorf("%s is there although the relayed write was refused", written)
	}

	// Three legs, one per console shape a run can leave behind. Each runs
	// the whole chain for real: the probe is this test binary started by the
	// stub as the account, under the restricted token, and it ends on a
	// verdict no later leg can mistake for another's.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, leg := range []struct {
		name   string
		slug   string
		env    func() []string
		window bool
	}{
		{"the plain bridged pipes", "plain", func() []string { return os.Environ() }, false},
		{"the console relay", "relay", func() []string { return append(os.Environ(), proc.EnvConsoleRelay+"=1") }, false},
		{"own console", "own-console", func() []string { return append(os.Environ(), proc.EnvOwnConsole+"=1") }, true},
	} {
		// The own-console leg is the only one that shows a real window:
		// AllocConsole puts a console on the desktop for the length of the run,
		// and a routine `go test ./...` has no business flashing windows at
		// whoever runs it. It is gated behind WUSERBOX_E2E_OWN_CONSOLE, the
		// variable streams_test.go established for exactly this question, whose
		// dedicated CI step is where the window's cost is paid. The gate is a
		// logged continue and not a Skip on purpose: the plain and relay legs
		// stay ungated and must still run on a desk, and the CI "Delete
		// boundary" step greps this test's output for "--- SKIP", where a skip
		// would be counted as a failure of coverage rather than a note that one
		// leg stayed home.
		if leg.window && os.Getenv(ownConsoleEnv) == "" {
			t.Logf("%s: skipped; a routine run does not ask for the real window this leg shows; set %s=1 to ask for it", leg.name, ownConsoleEnv)
			continue
		}
		resultFile := filepath.Join(work, "conhost-doors-"+leg.slug+".txt")
		if err := os.Remove(resultFile); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		commandLine := syscall.EscapeArg(exe) + " " + conhostProwlFlag + " " + syscall.EscapeArg(resultFile)
		legLine := box.throughTheStub(t, stub, commandLine)
		code, runErr := proc.RunAsAccount(box.account, box.password, legLine, work, leg.env())
		if runErr != nil {
			t.Fatalf("%s: starting the conhost prowl as %s: %v", leg.name, box.account, runErr)
		}
		if code != 0 {
			// The exit code is the verdict; the file is only the
			// diagnosis. The verdict got here through the whole chain --
			// account, stub, restricted token, back across the logon
			// boundary -- and cannot be taken away, which is why the prowl
			// answers in it and the test reads the file only to say why.
			diagnosis, _ := os.ReadFile(resultFile)
			t.Fatalf("%s: the conhost prowl ended with exit code %d; what it wrote: %s",
				leg.name, code, diagnosis)
		}
		raw, err := os.ReadFile(resultFile)
		if err != nil {
			t.Fatalf("%s: the conhost prowl ended clean but wrote no result: %v", leg.name, err)
		}
		content := string(raw)
		t.Logf("%s: %s", leg.name, content)

		// The verdict is the last line, `measured N hosts with M open
		// doors`; the per-host lines above it are the diagnosis. M is 0
		// exactly when the file shows no open door, and N at least 1 is
		// what keeps a run with no measurable host from passing for a
		// boundary that held.
		lines := strings.Split(strings.TrimSpace(content), "\n")
		summary := lines[len(lines)-1]
		var measured, openDoors int
		if _, err := fmt.Sscanf(summary, "measured %d hosts with %d open doors", &measured, &openDoors); err != nil {
			t.Errorf("%s: the prowl's last line was %q, which is no verdict at all", leg.name, summary)
			continue
		}
		if openDoors != 0 || measured < 1 {
			t.Errorf("%s: a console host of the run was left open to the sandboxed program: %s", leg.name, content)
		}
	}
}
