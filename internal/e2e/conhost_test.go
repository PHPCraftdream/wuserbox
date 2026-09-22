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
	// conhostProwlUnknown: at least one required check on a host the fresh
	// re-list still finds standing got no answer at all -- an error that is
	// neither the refusal a shut door gives nor the vanish of something
	// that ended. A boundary some of whose questions went unanswered is
	// not a boundary that held, and it is not a host that died either: the
	// re-list is what confirms a vanish, and this is what an unknown about
	// a host still standing ends on.
	conhostProwlUnknown = 47
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

// The names the checks carry. The two token legs are named apart on
// purpose (review round 4, P2-2): an OpenProcess failure and an
// OpenProcessToken failure are different machines breaking, and the
// verdict has to be able to say which of the two went unanswered.
const (
	prowlTokenProcessDoor   = "OpenProcess for the token"
	prowlTokenDoor          = "TOKEN_DUPLICATE|TOKEN_QUERY"
	prowlThreadContextDoor  = "THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME"
	prowlThreadWriteDacDoor = "THREAD_WRITE_DAC"
)

// The answer one required question came back as. A door either opened, was
// refused by the object's own list -- error 5, the answer shut doors give
// --, named a thread that had already ended -- error 87, the one vanish a
// walk tolerates --, was granted for something that opens nothing
// dangerous -- the ordinary QUERY_LIMITED handle the token door is reached
// through, proof the host was there to be asked and nothing more -- or
// came back as something the probe does not understand. That last one is
// no answer at all, and no answer is its own verdict: never a shut door,
// never a vanish.
type prowlAnswer int

const (
	prowlAnswerOpen     prowlAnswer = iota // the door itself was granted
	prowlAnswerShut                        // refused by the object's own list
	prowlAnswerGone                        // the id names a thread that has ended
	prowlAnswerOrdinary                    // granted, and grants nothing dangerous
	prowlAnswerUnknown                     // no answer the probe understands
)

// prowlCheck is one required question with the answer it got: the door
// asked -- process opens and token opens under names of their own, so the
// verdict can say which machine broke --, the thread it was asked about
// when it was a thread door, the answer, and the errno when the answer was
// none. The checks are what the verdict is computed from and the line is
// rendered from, which is the whole of review round 4 (P2-2): an unknown
// recorded next to definite answers has to survive into the verdict
// instead of washing out in an aggregate count.
type prowlCheck struct {
	door  string
	tid   uint32
	state prowlAnswer
	errno int
}

// prowlClassifyOpen sorts one open call's raw outcome into the check it
// answers. A handle is the door open; a refusal with error 5 is the
// object's own list answering; anything else is the door's own unknown,
// with the errno carried for the line.
func prowlClassifyOpen(door string, h uintptr, callErr error) prowlCheck {
	if h != 0 {
		return prowlCheck{door: door, state: prowlAnswerOpen}
	}
	refused, errno := prowlErrno(callErr)
	if refused {
		return prowlCheck{door: door, state: prowlAnswerShut}
	}
	return prowlCheck{door: door, state: prowlAnswerUnknown, errno: errno}
}

// prowlClassifyToken sorts the token open's outcome into the token door's
// own check. It is named for the token door and never for the process open
// that had to come first: an OpenProcessToken failure after a successful
// OpenProcess is the token question going unanswered about a host that was
// demonstrably there to be asked -- the review's own unclassified case,
// which used to be recorded nowhere at all (review round 4, P2-2). A
// refusal stays the shut answer it is.
func prowlClassifyToken(callErr error) prowlCheck {
	if callErr == nil {
		return prowlCheck{door: prowlTokenDoor, state: prowlAnswerOpen}
	}
	refused, errno := prowlErrno(callErr)
	if refused {
		return prowlCheck{door: prowlTokenDoor, state: prowlAnswerShut}
	}
	return prowlCheck{door: prowlTokenDoor, state: prowlAnswerUnknown, errno: errno}
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
	anyOpen, anyUnmeasured, anyUnknown := false, false, false
	for _, pid := range hosts {
		// Each host fetches its own threads, fresh when it is measured: a
		// snapshot taken once for the whole probe would be stale by the time
		// the later hosts came up, and a stale snapshot can only list the
		// threads that were already dead when it was taken.
		v := prowlMeasureHost(pid)
		anyOpen = anyOpen || len(v.open) > 0
		anyUnmeasured = anyUnmeasured || v.unmeasured
		anyUnknown = anyUnknown || v.unknown
		verdicts = append(verdicts, v)
	}

	// The dying-host refinement: doors found open -- hosts whose threads
	// could not be examined -- and required checks that got no answer are
	// only believed while the host is still there to be measured again. A
	// console whose host died between the walk and the probe -- expected
	// for a console freed mid-run -- leaves doors nobody can re-check, and
	// reporting those as an escape would make every run with a dying
	// console look guilty. The same mercy is owed to a host whose threads
	// could not be examined: a host that died cannot be asked about its
	// threads at all, and that is the honest gone case, not a hole. It is
	// owed to an unknown all the same, and only this fresh walk is allowed
	// to pay it: a vanish is positively confirmed by the re-list, never
	// assumed from an unclear answer, and a host the walk still finds
	// standing keeps its unknowns and fails the run on them. Re-list once
	// after a second and let prowlConfirmGone say which hosts are gone.
	if anyOpen || anyUnmeasured || anyUnknown {
		time.Sleep(time.Second)
		again, walkErr := proc.ConsoleHostChildren(uint32(os.Getppid()))
		if walkErr != nil {
			return conhostProwlBroken
		}
		still := make(map[uint32]bool, len(again))
		for _, pid := range again {
			still[pid] = true
		}
		prowlConfirmGone(verdicts, still)
	}

	measured, openDoors := 0, 0
	lines := make([]string, 0, len(verdicts)+1)
	for _, v := range verdicts {
		lines = append(lines, v.line)
		if v.measured {
			measured++
		}
		openDoors += len(v.open)
	}
	lines = append(lines, fmt.Sprintf("measured %d hosts with %d open doors", measured, openDoors))
	_ = os.WriteFile(resultFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	return prowlCode(verdicts)
}

// prowlConfirmGone is the re-list's verdict, and the only thing allowed to
// call a host gone: every host the fresh walk no longer lists has its
// doors, its unmeasured flag and its unknowns cleared, because a console
// host that died between the walk and the probe cannot be asked anything
// and the honest gone case is not a hole. The same host still listed keeps
// every answer it has, unknowns included, for prowlCode to fail on -- an
// unclear answer is never a vanish, and a vanish is never assumed from an
// unclear answer (review round 4, P2-2).
func prowlConfirmGone(verdicts []prowlVerdict, still map[uint32]bool) {
	for i, v := range verdicts {
		if (len(v.open) > 0 || v.unmeasured || v.unknown) && !still[v.pid] {
			v.line = fmt.Sprintf("host %d: gone before it could be measured again", v.pid)
			v.open = nil
			v.measured = false
			v.unmeasured = false
			v.unknown = false
			verdicts[i] = v
		}
	}
}

// prowlCode is the exit code these verdicts end the probe on, worst first:
// a door that opened is the escape itself and outranks every doubt about
// the measurement; then the required checks that got no answer about hosts
// still standing -- an unanswered question is not a shut door; then the
// hosts that answered their process doors but not a single thread of which
// could be examined, a measurement failure counted apart so an unmeasured
// boundary cannot pass for a held one; then the run that measured nothing
// at all. Only a probe whose every host was measured and whose every
// required check was answered ends zero.
func prowlCode(verdicts []prowlVerdict) int {
	measured, openDoors, unmeasuredAlive, unknownAlive := 0, 0, 0, 0
	for _, v := range verdicts {
		if v.measured {
			measured++
		}
		if v.unmeasured {
			unmeasuredAlive++
		}
		if v.unknown {
			unknownAlive++
		}
		openDoors += len(v.open)
	}
	switch {
	case openDoors > 0:
		return conhostProwlOpen
	case unknownAlive > 0:
		return conhostProwlUnknown
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
// -- unreachable and gone hosts are reported and counted as neither --
// whether the host answered its process doors while not one thread of it
// could be examined, which is what unmeasured exists to say, and whether
// any required check on it got no answer at all. That last flag is a
// verdict of its own (review round 4, P2-2): one definite answer never
// redeems an unknown about a different door or thread, and an unknown is
// neither a shut door nor a vanished host -- only the fresh re-list may
// turn it into a vanish, by finding the host gone.
type prowlVerdict struct {
	pid        uint32
	line       string
	open       []string
	measured   bool
	unmeasured bool
	unknown    bool
}

// prowlVerdictOf is the prowl's arithmetic, kept apart from every open so
// it can be checked on a desk with no doors at all: from the checks one
// host's measurement gathered it says which doors opened, whether any
// thread of the host was definitely examined, whether the host answered
// its process doors while not one thread of it could be had, and whether
// any required check on it got no answer at all. That last flag stands on
// its own and stands forever: a later pass answering other questions does
// not unask the one that went unanswered. A vanish is not for the checks
// to imply either -- a check that names a thread gone is only the words
// "ended between the doors" on the line, and calling a whole host gone is
// the fresh re-list's alone (prowlConfirmGone). The walk's own complaint,
// when the walk itself broke, comes in as walkSaid and goes on the line
// last, where the diagnosis reads.
func prowlVerdictOf(pid uint32, process, threads []prowlCheck, walkSaid []string) prowlVerdict {
	v := prowlVerdict{pid: pid}
	var notes []string
	examined := make(map[uint32]bool)
	for _, c := range process {
		switch c.state {
		case prowlAnswerOpen:
			v.open = append(v.open, c.door)
		case prowlAnswerUnknown:
			v.unknown = true
			notes = append(notes, fmt.Sprintf("%s (errno %d)", c.door, c.errno))
		}
	}
	for _, c := range threads {
		switch c.state {
		case prowlAnswerOpen:
			v.open = append(v.open, c.door)
			examined[c.tid] = true
		case prowlAnswerShut:
			examined[c.tid] = true
		case prowlAnswerGone:
			notes = append(notes, fmt.Sprintf("thread %d ended between the doors", c.tid))
		case prowlAnswerUnknown:
			v.unknown = true
			notes = append(notes, fmt.Sprintf("%s of thread %d (errno %d)", c.door, c.tid, c.errno))
		}
	}
	notes = append(notes, walkSaid...)
	// The count of threads actually examined goes on the line when there
	// was one; when there was none, the line says so instead of leaving a
	// "closed" that only means nobody could ask.
	v.measured = len(examined) > 0
	v.unmeasured = !v.measured
	line := fmt.Sprintf("host %d: closed", pid)
	if len(v.open) > 0 {
		line = fmt.Sprintf("host %d: open doors %s", pid, strings.Join(v.open, ", "))
	}
	if v.measured {
		line += fmt.Sprintf(" (%d threads tried)", len(examined))
	} else {
		line += " (no thread of it would answer)"
	}
	if len(notes) > 0 {
		line += " (" + strings.Join(notes, ", ") + ")"
	}
	v.line = line
	return v
}

// prowlMeasureHost tries every door on one console host and says what
// opened. It fetches the host's threads itself, fresh when it is measured --
// see prowlThreadsOfOwner for why the snapshot is not shared between hosts.
// Every open's outcome is sorted into a prowlCheck as it happens -- the
// door asked, the answer, the errno when there was no answer -- and the
// checks, not loose notes, are what the verdict is computed from: an
// unknown recorded next to definite answers has to survive into the
// verdict instead of washing out in an aggregate count (review round 4,
// P2-2).
func prowlMeasureHost(pid uint32) prowlVerdict {
	var process, threads []prowlCheck

	// A dangerous door: a handle is the door open; a refusal with error 5
	// is the object's own list answering, which is the fix working;
	// anything else is the probe not understanding the machine it runs on
	// and is the door's own unknown -- on the line, and on the verdict,
	// never read as a shut door.
	for _, door := range prowlProcessDoors {
		h, _, callErr := prowlOpenProcess.Call(door.access, 0, uintptr(pid))
		if h != 0 {
			syscall.CloseHandle(syscall.Handle(h))
		}
		process = append(process, prowlClassifyOpen(door.name, h, callErr))
	}

	// The token door goes through the one open every account has: a handle
	// for QUERY_LIMITED_INFORMATION is ordinary -- proof the host was there
	// to be asked, and nothing more -- and the token behind it is not
	// supposed to be duplicable by the program the host was started for.
	// What the token open itself answers is the token door's own check,
	// under the token door's own name: an OpenProcessToken failure after a
	// successful OpenProcess is an unknown of its own class, never dropped
	// and never folded into a process-open result (review round 4, P2-2).
	h, _, callErr := prowlOpenProcess.Call(prowlProcessQueryLimited, 0, uintptr(pid))
	if h != 0 {
		process = append(process, prowlCheck{door: prowlTokenProcessDoor, state: prowlAnswerOrdinary})
		var token syscall.Token
		tokenErr := syscall.OpenProcessToken(syscall.Handle(h), prowlTokenDuplicateQuery, &token)
		if tokenErr == nil {
			token.Close()
		}
		process = append(process, prowlClassifyToken(tokenErr))
		syscall.CloseHandle(syscall.Handle(h))
	} else {
		process = append(process, prowlClassifyOpen(prowlTokenProcessDoor, h, callErr))
	}

	// A host every open of which failed with something other than a refusal
	// is a pid that died between the walk and the probe, not a shut one --
	// saying so keeps a broken measurement from passing for a boundary. The
	// unknown answers stay on the verdict all the same: that the pid really
	// died is the fresh re-list's to confirm, and a host the re-list still
	// finds standing is a live host nothing could be asked about, which
	// ends the run on conhostProwlUnknown of its own.
	allUnknown := true
	for _, c := range process {
		if c.state != prowlAnswerUnknown {
			allUnknown = false
			break
		}
	}
	if allUnknown {
		errno := 0
		for _, c := range process {
			if c.state == prowlAnswerUnknown && c.errno != 0 {
				errno = c.errno
				break
			}
		}
		return prowlVerdict{
			pid:     pid,
			line:    fmt.Sprintf("host %d: unreachable (errno %d)", pid, errno),
			unknown: true,
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
		threadsListed, walkOK := prowlThreadsOfOwner(pid)
		if !walkOK {
			// The walk itself broke -- the snapshot could not be taken, or
			// ended in something other than its normal 18. Nothing was
			// examined and nothing can be -- every pass that examined a
			// thread broke out of the loop before this one -- so say so
			// and stop, rather than retry a machine that has stopped
			// answering.
			walkFailed = true
			break
		}
		for _, tid := range threadsListed {
			// Door A first, the dangerous one. A handle here makes the host
			// guilty regardless of anything else -- the door IS the escape
			// -- so the thread counts as examined and door B is never
			// asked: there is no point asking more of a thread already
			// proven open.
			h, _, openErr := prowlOpenThread.Call(prowlThreadSetContextResume, 0, uintptr(tid))
			if h != 0 {
				syscall.CloseHandle(syscall.Handle(h))
				threads = append(threads, prowlCheck{door: prowlThreadContextDoor, tid: tid, state: prowlAnswerOpen})
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
					syscall.CloseHandle(syscall.Handle(hB))
					threads = append(threads,
						prowlCheck{door: prowlThreadContextDoor, tid: tid, state: prowlAnswerShut},
						prowlCheck{door: prowlThreadWriteDacDoor, tid: tid, state: prowlAnswerOpen})
					examined++
				} else if refusedB, goneB, errnoB := prowlThreadErrno(openErrB); refusedB {
					// Refused twice, dangerous and narrow alike: the only
					// shape counted as a shut thread, an answer the
					// thread's own list gave about both doors.
					threads = append(threads,
						prowlCheck{door: prowlThreadContextDoor, tid: tid, state: prowlAnswerShut},
						prowlCheck{door: prowlThreadWriteDacDoor, tid: tid, state: prowlAnswerShut})
					examined++
				} else if goneB {
					// The thread ended between the two doors. The
					// dangerous door already answered shut before it
					// vanished, so the thread still counts as examined
					// -- but the vanish is on the record, because a thread
					// dying under the probe is worth a word in the
					// diagnosis.
					threads = append(threads,
						prowlCheck{door: prowlThreadContextDoor, tid: tid, state: prowlAnswerShut},
						prowlCheck{door: prowlThreadWriteDacDoor, tid: tid, state: prowlAnswerGone})
					examined++
				} else {
					// Not a refusal and not a vanish: the machine is not
					// answering the question that was asked, and that
					// must never count as a door closed -- the thread
					// stays unexamined and the door's own unknown is what
					// the verdict fails on.
					threads = append(threads,
						prowlCheck{door: prowlThreadContextDoor, tid: tid, state: prowlAnswerShut},
						prowlCheck{door: prowlThreadWriteDacDoor, tid: tid, state: prowlAnswerUnknown, errno: errnoB})
				}
			case goneA:
				// The thread ended between the snapshot and the open --
				// the expected vanish every walk tolerates, Windows
				// answering 87 because the id now names nothing. The
				// thread is skipped entirely: not examined, not guilty,
				// not noted, and no check at all -- it was never asked
				// anything.
			default:
				// Neither a refusal nor a vanish, and no handle: the same
				// rule the process doors keep, an error the probe does
				// not understand is the door's own unknown -- the thread
				// stays unexamined and the verdict fails on it, never a
				// door closed by accident.
				threads = append(threads, prowlCheck{door: prowlThreadContextDoor, tid: tid, state: prowlAnswerUnknown, errno: errnoA})
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

	// The walk's own complaint goes in last, where the diagnosis reads.
	var walkSaid []string
	if walkFailed {
		walkSaid = append(walkSaid, "the thread walk itself failed")
	}
	return prowlVerdictOf(pid, process, threads, walkSaid)
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
// Since review round 4 (P2-2) every open's outcome is sorted into a check
// the verdict is computed from, and an unknown -- a required check that
// got no answer at all -- is a verdict of its own: the token open that
// fails after its process open succeeded, the door that answers neither a
// refusal nor a vanish next to doors that were answered, the thread whose
// question went unanswered while another thread's was taken. None of them
// washes out in an aggregate any more, and none of them is read as a
// vanished host either: vanishing is the fresh re-list's to confirm, and a
// host it still finds standing ends the run on its unknowns (exit code
// 47). The verdict arithmetic is plain data -- prowlVerdictOf, prowlCode,
// prowlConfirmGone -- and its own tests below run with no doors at all.
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
	// the whole chain for real: the probe is the stub copy -- the same test
	// binary stubBinary put where the account can start it -- started by the
	// stub as the account, under the restricted token, and it ends on a
	// verdict no later leg can mistake for another's. The copy and not the
	// raw os.Executable() path is named for the same reason the stub itself
	// is started from the copy: starting an image means reading it, the
	// original lives under the temporary directory of whoever ran the
	// tests, and the account is not that person -- measured on CI as the
	// stub's own "access is denied" at CreateProcess, before a single
	// console host of the run existed to be measured.
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
		commandLine := syscall.EscapeArg(stub) + " " + conhostProwlFlag + " " + syscall.EscapeArg(resultFile)
		legLine := box.throughTheStub(t, stub, commandLine)
		// The stub's last words go to its stderr, and a run carries that
		// stderr only when the caller's own streams are consoles -- under
		// `go test` they are pipes, so runAsAccount builds no bridge for it
		// and whatever the stub said before dying is lost exactly where the
		// failure happened. RunAsAccount takes the child's output handles
		// from os.Stdout and os.Stderr synchronously inside the call, so
		// pointing os.Stderr at a file for exactly the length of the call
		// is enough for the stub and everything it starts to write there,
		// while the test's own output stays untouched. No defer inside the
		// loop: the swap is undone and the file closed before the next leg.
		stubStderr, err := os.Create(filepath.Join(work, "stub-stderr-"+leg.slug+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		wasStderr := os.Stderr
		os.Stderr = stubStderr
		code, runErr := proc.RunAsAccount(box.account, box.password, legLine, work, leg.env())
		os.Stderr = wasStderr
		stubStderr.Close()
		if runErr != nil {
			t.Fatalf("%s: starting the conhost prowl as %s: %v", leg.name, box.account, runErr)
		}
		if code != 0 {
			// The exit code is the verdict; the file is only the
			// diagnosis. The verdict got here through the whole chain --
			// account, stub, restricted token, back across the logon
			// boundary -- and cannot be taken away, which is why the prowl
			// answers in it and the test reads the file only to say why.
			//
			// Exit code 90 is never one of the prowl's verdicts -- 42
			// through 47 are the six the prowl ends on. 90 is
			// account_test.go's TestMain answering for exec.Stub having
			// returned an error, the stub's own refusal or breakage, so the
			// doors were never measured at all and the number must not be
			// read as an open-door count. The stub's own words on its way
			// out are the only diagnosis that exists for that shape, and
			// the file captured above is where they now live: this reads
			// them back when the verdict is bad -- the same split as the
			// prowl's exit code and its result file, and the same
			// diagnostic discipline as shield.go's thread-refusal words.
			// The check itself is unchanged, only what a failure is able
			// to say.
			diagnosis, _ := os.ReadFile(resultFile)
			stubWords, readErr := os.ReadFile(filepath.Join(work, "stub-stderr-"+leg.slug+".txt"))
			stubSaid := string(stubWords)
			if readErr != nil {
				stubSaid = fmt.Sprintf("unreadable: %v", readErr)
			}
			t.Fatalf("%s: the conhost prowl ended with exit code %d; what it wrote: %s; what the stub's stderr carried: %s",
				leg.name, code, diagnosis, stubSaid)
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

// The verdict arithmetic's own tests, on a desk with no doors: review
// round 4 (P2-2) asks that a partially unknown measurement cannot pass,
// and asks that the demand be checkable without windows accounts, without
// elevation and without a real dangerous open -- the checks and the code
// they end on are plain data now, so these tests feed synthetic ones
// straight to the arithmetic and read the verdict back.

// TestAnUnknownAnswerAboutAStillLivingHostFailsTheProwl is the review's own
// case: one required check definitely answered -- a door refused, a thread
// examined -- next to one that got no answer at all, on a host still
// standing. One definite answer never redeemed the unknown before only
// because the aggregates never looked at it: the unanswered door sat in
// the notes while the measured count and the open count both came back
// clean. The verdict carries the unknown on its own now, and the probe
// ends on conhostProwlUnknown for it -- whether the unknown is a process
// door's or a thread door's next to a thread that was examined.
func TestAnUnknownAnswerAboutAStillLivingHostFailsTheProwl(t *testing.T) {
	for _, tt := range []struct {
		name    string
		process []prowlCheck
		threads []prowlCheck
	}{
		{
			"a process door unanswered next to a process door refused",
			[]prowlCheck{
				{door: "PROCESS_VM_WRITE", state: prowlAnswerShut},
				{door: "PROCESS_DUP_HANDLE", state: prowlAnswerUnknown, errno: 6},
			},
			[]prowlCheck{
				{door: prowlThreadContextDoor, tid: 5, state: prowlAnswerShut},
				{door: prowlThreadWriteDacDoor, tid: 5, state: prowlAnswerShut},
			},
		},
		{
			"a thread door unanswered next to a thread examined",
			[]prowlCheck{{door: "PROCESS_ALL_ACCESS", state: prowlAnswerShut}},
			[]prowlCheck{
				{door: prowlThreadContextDoor, tid: 7, state: prowlAnswerShut},
				{door: prowlThreadContextDoor, tid: 8, state: prowlAnswerUnknown, errno: 6},
			},
		},
	} {
		v := prowlVerdictOf(4242, tt.process, tt.threads, nil)
		if !v.unknown {
			t.Errorf("%s: the verdict carries no unknown although a required check got no answer", tt.name)
		}
		if !v.measured {
			t.Errorf("%s: the host was measured -- its definite answers stand -- and the verdict has to say so", tt.name)
		}
		if got := prowlCode([]prowlVerdict{v}); got != conhostProwlUnknown {
			t.Errorf("%s: the probe ends %d on a partially unknown measurement, not conhostProwlUnknown", tt.name, got)
		}
	}

	// The positive control: the same host with every check answered ends
	// zero, so what turns the code below is the unknown and not the company
	// it keeps.
	shut := prowlVerdictOf(4242,
		[]prowlCheck{{door: "PROCESS_VM_WRITE", state: prowlAnswerShut}},
		[]prowlCheck{{door: prowlThreadContextDoor, tid: 5, state: prowlAnswerShut}}, nil)
	if shut.unknown || shut.unmeasured {
		t.Errorf("a host whose every check was answered came back unknown %v unmeasured %v", shut.unknown, shut.unmeasured)
	}
	if got := prowlCode([]prowlVerdict{shut}); got != 0 {
		t.Errorf("the probe ends %d on a measurement whose every check was answered", got)
	}
}

// TestATokenOpenFailingAfterASuccessfulProcessOpenIsAnUnknownOfItsOwn is
// the shape the review caught falling through unclassified: the process
// open for the token leg succeeded -- the host was demonstrably there to
// be asked -- and the token open behind it failed with something that is
// no refusal. That outcome used to be recorded nowhere at all: no door
// counted open, no note the aggregates read, a required check silently
// gone. It is the token door's own unknown now, under the token door's own
// name -- never folded into the process open's result and never into a
// process door's -- and a verdict holding it next to doors that were
// answered ends the probe on conhostProwlUnknown.
func TestATokenOpenFailingAfterASuccessfulProcessOpenIsAnUnknownOfItsOwn(t *testing.T) {
	c := prowlClassifyToken(syscall.Errno(6))
	if c.state != prowlAnswerUnknown {
		t.Errorf("a token open failed with errno 6, which is no refusal, and was classified %v", c.state)
	}
	if c.door != prowlTokenDoor {
		t.Errorf("the token open's unknown answers under %q, not the token door's own name", c.door)
	}
	// The classes stay apart: the process open's own failure keeps its own
	// check under its own name, and the two never share one bucket.
	p := prowlClassifyOpen(prowlTokenProcessDoor, 0, syscall.Errno(6))
	if p.state != prowlAnswerUnknown {
		t.Errorf("a process open failed with errno 6, which is no refusal, and was classified %v", p.state)
	}
	if p.door != prowlTokenProcessDoor {
		t.Errorf("the process open's unknown answers under %q, not its own name", p.door)
	}

	// And the whole verdict: the ordinary handle proves the host was there,
	// the dangerous door was refused, the token question went unanswered,
	// a thread was examined -- and the run still fails, on the unknown's
	// own code, which is the review's demand.
	v := prowlVerdictOf(99, []prowlCheck{
		{door: "PROCESS_ALL_ACCESS", state: prowlAnswerShut},
		{door: prowlTokenProcessDoor, state: prowlAnswerOrdinary},
		c,
	}, []prowlCheck{{door: prowlThreadContextDoor, tid: 3, state: prowlAnswerShut}}, nil)
	if !v.unknown {
		t.Error("the verdict carries no unknown although the token question went unanswered")
	}
	if got := prowlCode([]prowlVerdict{v}); got != conhostProwlUnknown {
		t.Errorf("the probe ends %d on an unanswered token question, not conhostProwlUnknown", got)
	}

	// The refusal itself is still the shut answer, so the door is read as
	// shut exactly when the object's own list said so and never otherwise.
	if got := prowlClassifyToken(prowlAccessDenied); got.state != prowlAnswerShut {
		t.Errorf("a token open refused with error 5 was classified %v, not shut", got.state)
	}
}

// TestAHostIsOnlyGoneWhenTheFreshWalkSaysSo pins the other half of the same
// rule: vanishing is its own outcome, positively confirmed by the fresh
// re-list, and an unclear answer never implies it. A verdict carrying
// unknowns whose host the re-list no longer lists is cleared to the gone
// line and counted nowhere; the same verdict with the host still listed is
// kept whole and ends the probe on the unknown's own code; and the lone
// host confirmed gone still ends conhostProwlNothingMeasured, because a
// run that measured nothing is not a boundary that held either.
func TestAHostIsOnlyGoneWhenTheFreshWalkSaysSo(t *testing.T) {
	host := prowlVerdictOf(7,
		[]prowlCheck{{door: "PROCESS_VM_WRITE", state: prowlAnswerUnknown, errno: 6}}, nil, nil)

	kept := []prowlVerdict{host}
	prowlConfirmGone(kept, map[uint32]bool{7: true})
	if !kept[0].unknown {
		t.Error("the fresh walk still lists the host, and its unknown was cleared anyway")
	}
	if got := prowlCode(kept); got != conhostProwlUnknown {
		t.Errorf("the probe ends %d on an unknown about a host the re-list still finds standing", got)
	}

	gone := []prowlVerdict{host}
	prowlConfirmGone(gone, nil)
	if gone[0].unknown || gone[0].unmeasured || gone[0].measured || len(gone[0].open) > 0 {
		t.Error("a host confirmed gone kept flags only a live host is allowed to carry")
	}
	if got := prowlCode(gone); got != conhostProwlNothingMeasured {
		t.Errorf("the probe ends %d after the only host was confirmed gone, not conhostProwlNothingMeasured", got)
	}
}
