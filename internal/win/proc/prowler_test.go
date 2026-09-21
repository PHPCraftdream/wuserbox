// The prowler and what it tries: the measurement apparatus behind
// docs/investigations/the-window-before-the-shield.md. What each door is,
// why a door is answered through an exit code rather than a file, and what a
// restricted token turns out to reach are all argued at the point they are
// tried, below.

package proc

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// The access rights a program under a restricted token must not get to the
// process that restricted it. Any one of them is enough to undo the
// restriction: two of them write into it, and the third reaches the one
// object worth taking -- its unrestricted token, which can be duplicated and
// then worn, for the same user, without any privilege at all.
const (
	processAllAccess        = 0x1FFFFF
	processCreateThread     = 0x0002
	processSetInformation   = 0x0200
	processVMOperation      = 0x0008
	processVMWrite          = 0x0020
	processDupHandle        = 0x0040
	processQueryInformation = 0x0400
	writeOwner              = 0x80000

	tokenDuplicateAccess   = 0x0002
	tokenImpersonateAccess = 0x0004
	securityImpersonation  = 2
	tokenImpersonation     = 2
	// currentThread is the pseudo-handle every thread has to itself, and
	// classImpersonationLevel is TokenImpersonationLevel -- together, what
	// the calling thread is actually wearing rather than what the call that
	// put it there returned.
	currentThread           = ^uintptr(1)
	classImpersonationLevel = 9
)

var (
	procOpenProcess             = w32.Kernel32.NewProc("OpenProcess")
	procOpenThreadToken         = w32.Advapi32.NewProc("OpenThreadToken")
	procDuplicateTokenEx        = w32.Advapi32.NewProc("DuplicateTokenEx")
	procImpersonateLoggedOnUser = w32.Advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf            = w32.Advapi32.NewProc("RevertToSelf")
	procIsTokenRestricted       = w32.Advapi32.NewProc("IsTokenRestricted")
)

// The doors, one bit each, answered through the exit code and not through a
// file. The first attempt at this wrote its findings to disk and reported
// nothing at all, because a program under a restricted token could not write
// them -- a measurement that a refusal elsewhere had quietly turned into
// silence. An exit code is the one channel the thing under test cannot take
// away.
const (
	reachedAllAccess = 1 << iota
	reachedDupHandle
	reachedVMWrite
	reachedVMOperation
	reachedCreateThread
	reachedSetInformation
	reachedWriteOwner
	reachedQuery
	reachedToken
	reachedWriteDac
	rewroteItsList
	woreAnUnrestrictedToken
	reachedThread
	reachedThreadList
	reachedBadPid
	// The control, and the one bit that has to be set. Shutting a process to
	// its own account could as easily have shut the program out of *itself*,
	// and a great many programs open their own process by name. A run where
	// that stopped working would be a boundary nobody could use.
	openedItself
	// Set on nothing the program found: it is how the stand-in in the middle
	// says it broke before it could be turned on at all. Kept far away from
	// the bits above, because a small ordinal added to them collides -- 93
	// through 97 are reachable as sums of the doors, and a stub that failed
	// would have been read as a program that got in.
	middleBroke = 1 << 20
	// Set when a thread door could not be answered at all: an OpenThread error
	// that is neither a refusal nor a thread that ended, or threads listed of
	// which none answered before they all vanished. One bit higher than
	// middleBroke for the same reason middleBroke is where it is -- that bit is
	// taken, and a small ordinal here would collide with the sums of the door
	// bits above -- and out of doorsReached on purpose, because a probe that
	// reports nothing must not be readable as a shut door.
	threadProbeBroke = 1 << 21
)

// The other door into a process, and the reason shutting the process alone
// would not have settled this: a thread is an object of its own with a list
// of its own, and one whose instructions can be redirected runs code inside
// the process that owns it. Shield closes all three; this is what tries them.
const (
	threadSetContext    = 0x0010
	threadSuspendResume = 0x0002
)

// threadsOfOwner lists every thread belonging to pid, walking the same
// snapshot Shield's own walk walks -- which is the point: the prowler looks
// for exactly what Shield claims to have shut, all of it and not the first
// thread the snapshot happens to name. A second thread left open while the
// first was shut is exactly the hole one-thread probing cannot see
// (docs/reviews/security-performance-review-2026-09-22-round2.md, P2-2).
//
// The bool is the walk itself: true when it ran to its errno-18 end, false
// when the snapshot could not be taken or the walk broke part way -- in both
// of which the ids are not every thread the process owns and say so.
func threadsOfOwner(pid int) ([]uint32, bool) {
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(snapshotOfThreads, 0)
	if snapshot == 0 || snapshot == invalidHandle {
		return nil, false
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	entry := make([]byte, sizeOfThreadEntry32)
	*(*uint32)(unsafe.Pointer(&entry[0])) = sizeOfThreadEntry32
	var ids []uint32
	for step := procThread32First; ; step = procThread32Next {
		r, _, listErr := step.Call(snapshot, uintptr(unsafe.Pointer(&entry[0])))
		if r == 0 {
			if errors.Is(listErr, syscall.Errno(errNoMoreItems)) {
				return ids, true
			}
			return nil, false
		}
		if *(*uint32)(unsafe.Pointer(&entry[offsetOfOwnerProcess])) == uint32(pid) {
			ids = append(ids, *(*uint32)(unsafe.Pointer(&entry[offsetOfThreadID])))
		}
	}
}

// rewriteAndWearItsToken is the way in that a list cannot close on its own,
// and the reason a deny entry naming the account was not the end of this.
//
// Windows grants the owner of an object READ_CONTROL and WRITE_DAC whatever
// its list says, so that an object can never be locked away from the person
// it belongs to. The stub and the program are owned by the same account, so
// refusing that account in the list refuses it nothing: it opens the process
// for WRITE_DAC, writes a list that allows everything, and walks in through
// the front door it has just unlocked.
//
// This is the whole chain rather than the first step, because the first step
// alone could be argued about. Rewrite the list, take the token, duplicate
// it, wear it -- and then ask whether what is being worn is restricted. If it
// is not, the second access check is gone and the boundary with it.
func rewriteAndWearItsToken(pid int) int {
	h, _, _ := procOpenProcess.Call(writeDac, 0, uintptr(pid))
	if h == 0 {
		return 0
	}
	defer syscall.CloseHandle(syscall.Handle(h))

	me, err := sid.CurrentUser()
	if err != nil {
		return reachedWriteDac
	}
	dacl, free, err := listAllowing(me)
	if err != nil {
		return reachedWriteDac
	}
	defer free()
	if r, _, _ := procSetSecurityInfo.Call(h, seKernelObject,
		daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, dacl, 0); r != 0 {
		return reachedWriteDac
	}
	reached := reachedWriteDac | rewroteItsList

	q, _, _ := procOpenProcess.Call(processQueryInformation, 0, uintptr(pid))
	if q == 0 {
		return reached
	}
	defer syscall.CloseHandle(syscall.Handle(q))
	var stolen syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(q),
		tokenDuplicateAccess|syscall.TOKEN_QUERY|tokenImpersonateAccess, &stolen); err != nil {
		return reached
	}
	defer stolen.Close()

	var worn syscall.Token
	if r, _, _ := procDuplicateTokenEx.Call(uintptr(stolen), syscall.TOKEN_ALL_ACCESS, 0,
		securityImpersonation, tokenImpersonation, uintptr(unsafe.Pointer(&worn))); r == 0 {
		return reached
	}
	defer worn.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if r, _, _ := procImpersonateLoggedOnUser.Call(uintptr(worn)); r == 0 {
		return reached
	}
	defer procRevertToSelf.Call()
	// Both questions, not just the second one. ImpersonateLoggedOnUser
	// returns nonzero even when what the thread ends up wearing is only good
	// for identification -- a level that answers "who is this" and opens
	// nothing -- and a restricted process wearing a token of its own user
	// gets exactly that. Measured: the same duplicate reaches impersonation
	// level from an unrestricted process and identification level from a
	// restricted one, and only the first can then write somewhere its own
	// token could not.
	//
	// Asking only whether the duplicate was unrestricted therefore reported
	// an escape that had not happened, and made the window before Shield
	// look like token theft when what actually works in it is putting code
	// inside the process instead.
	if level, err := impersonationLevel(); err != nil || level < securityImpersonation {
		return reached
	}
	if restricted, _, _ := procIsTokenRestricted.Call(uintptr(worn)); restricted == 0 {
		reached |= woreAnUnrestrictedToken
	}
	return reached
}

// impersonationLevel reads the level the calling thread is actually wearing,
// which is the part ImpersonateLoggedOnUser's return value does not say.
func impersonationLevel() (uint32, error) {
	var thread syscall.Token
	if r, _, callErr := procOpenThreadToken.Call(currentThread, syscall.TOKEN_QUERY, 1,
		uintptr(unsafe.Pointer(&thread))); r == 0 {
		return 0, callErr
	}
	defer thread.Close()
	var level uint32
	var got uint32
	if err := syscall.GetTokenInformation(thread, classImpersonationLevel,
		(*byte)(unsafe.Pointer(&level)), uint32(unsafe.Sizeof(level)), &got); err != nil {
		return 0, err
	}
	return level, nil
}

// listAllowing builds a permission list that hands everything to one
// identifier, which is what an owner writes once it has WRITE_DAC.
func listAllowing(who string) (dacl uintptr, free func(), err error) {
	var descriptor uintptr
	text := fmt.Sprintf("D:P(A;;GA;;;%s)", who)
	if r, _, callErr := procStringToSecurityDescriptor.Call(uintptr(unsafe.Pointer(w32.UTF16(text))), 1,
		uintptr(unsafe.Pointer(&descriptor)), 0); r == 0 {
		return 0, nil, callErr
	}
	var present, defaulted int32
	if r, _, callErr := procGetSecurityDescriptorDacl.Call(descriptor, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		w32.Free(descriptor)
		return 0, nil, callErr
	}
	return dacl, func() { w32.Free(descriptor) }, nil
}

// prowl is the program at the end of the chain turning on the one that
// started it. Running under the restricted token, as the same account, it
// tries every door into that process worth trying and ends on what opened.
func prowl(parentPid string) int {
	pid, err := strconv.Atoi(parentPid)
	if err != nil {
		return reachedBadPid
	}
	reached := 0
	opened := func(bit int, access uintptr) syscall.Handle {
		h, _, _ := procOpenProcess.Call(access, 0, uintptr(pid))
		if h == 0 {
			return 0
		}
		reached |= bit
		return syscall.Handle(h)
	}
	// One right at a time, and not only the useful combinations. Asking for
	// everything and being refused says nothing about any single right in it:
	// the first version of this asked for PROCESS_ALL_ACCESS, was refused,
	// and reported a process that was still wide open to WRITE_DAC on its
	// own. A refusal of a set is not a refusal of its members.
	for _, door := range []struct {
		bit    int
		access uintptr
	}{
		{reachedAllAccess, processAllAccess},
		{reachedDupHandle, processDupHandle},
		{reachedVMWrite, processVMWrite},
		{reachedVMOperation, processVMOperation},
		{reachedCreateThread, processCreateThread},
		{reachedSetInformation, processSetInformation},
		{reachedWriteOwner, writeOwner},
	} {
		if h := opened(door.bit, door.access); h != 0 {
			syscall.CloseHandle(h)
		}
	}
	// The one worth having: its token, which is the account's ordinary one.
	if h := opened(reachedQuery, processQueryInformation); h != 0 {
		var stolen syscall.Token
		if err := syscall.OpenProcessToken(h, tokenDuplicateAccess, &stolen); err == nil {
			reached |= reachedToken
			stolen.Close()
		}
		syscall.CloseHandle(h)
	}
	reached |= rewriteAndWearItsToken(pid)
	// And the other door: its threads, each of them an object of its own with
	// a list of its own, none shut by shutting the process. Every thread the
	// walk lists is tried, and every door on it comes back answered: a handle
	// means the door opened, a refusal means the door held, a thread that
	// ended between the listing and the open answers nothing and is nobody,
	// and anything else means the probe itself broke -- its own bit, far from
	// the doors, because a probe that reports nothing must not be readable as
	// a shield that holds.
	ids, listed := threadsOfOwner(pid)
	examined := 0
	for _, tid := range ids {
		answered := false
		for _, door := range []struct {
			bit    int
			access uintptr
		}{
			{reachedThread, threadSetContext | threadSuspendResume},
			{reachedThreadList, writeDac},
		} {
			h, _, callErr := procOpenThread.Call(door.access, 0, uintptr(tid))
			switch {
			case h != 0:
				reached |= door.bit
				syscall.CloseHandle(syscall.Handle(h))
				answered = true
			case errors.Is(callErr, syscall.Errno(errInvalidParameter)):
				// The thread ended while this was being asked; it names
				// nothing now and is held against neither the door nor
				// the probe.
			case errors.Is(callErr, syscall.ERROR_ACCESS_DENIED):
				// A refusal is an answer: the door held.
				answered = true
			default:
				// The probe could not ask, which is not the same as the
				// door holding.
				reached |= threadProbeBroke
				answered = true
			}
		}
		if answered {
			examined++
		}
	}
	if !listed || (len(ids) > 0 && examined == 0) {
		reached |= threadProbeBroke
	}
	// Itself, by name and not through the handle every process has to itself,
	// which is never checked against a list.
	if h, _, _ := procOpenProcess.Call(processAllAccess, 0, uintptr(os.Getpid())); h != 0 {
		reached |= openedItself
		syscall.CloseHandle(syscall.Handle(h))
	}
	return reached
}

// stubby stands in for the stub as it really is, which the plain middle above
// does not: it narrows its own token, shuts itself to the account both it and
// the program run as, and only then starts the program under the narrow
// token. It ends on whatever the program found, so the test outside reads one
// number and never has to reach across the chain for a file.
//
// The order is the property. Shielding after the program has started would
// leave exactly the window this exists to close.
func stubby() int {
	restricted, err := token.AsSandbox(nobodysGroup, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "stubby: restricting its own token:", err)
		return middleBroke | 1
	}
	defer restricted.Close()
	if err := Shield(); err != nil {
		fmt.Fprintln(os.Stderr, "stubby: shutting itself to its own account:", err)
		return middleBroke | 2
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "stubby:", err)
		return middleBroke | 3
	}
	here, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "stubby:", err)
		return middleBroke | 4
	}
	line := strings.Join([]string{
		syscall.EscapeArg(exe), prowlerFlag, syscall.EscapeArg(fmt.Sprint(os.Getpid())),
	}, " ")
	code, err := Run(restricted, line, here)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stubby: starting the program:", err)
		return middleBroke | 5
	}
	return code
}

// doorsReached spells out an exit code from prowl.
func doorsReached(code int) string {
	named := []struct {
		bit  int
		what string
	}{
		{reachedAllAccess, "everything"},
		{reachedDupHandle, "duplicating its handles"},
		{reachedVMWrite, "writing its memory"},
		{reachedQuery, "asking about it"},
		{reachedToken, "duplicating its token"},
		{reachedWriteDac, "opening it to rewrite its permission list"},
		{rewroteItsList, "rewriting its permission list"},
		{woreAnUnrestrictedToken, "wearing its unrestricted token"},
		{reachedVMOperation, "operating on its memory"},
		{reachedCreateThread, "creating a thread in it"},
		{reachedSetInformation, "setting information on it"},
		{reachedWriteOwner, "taking ownership of it"},
		{reachedThread, "redirecting one of its threads"},
		{reachedThreadList, "rewriting one of its threads' permission list"},
		{reachedBadPid, "(it was not given a readable pid)"},
	}
	var got []string
	for _, one := range named {
		if code&one.bit != 0 {
			got = append(got, one.what)
		}
	}
	if len(got) == 0 {
		return "nothing"
	}
	return strings.Join(got, ", ")
}
