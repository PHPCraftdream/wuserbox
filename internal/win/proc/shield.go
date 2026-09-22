// Shutting a process to the account it is itself running as.
//
// This is the one thing the two-process shape needs that a one-process shape
// never did, and it is enough code to want a file of its own -- which puts
// internal/win/proc at eight entries where the layout rules ask for about
// seven. Named rather than quietly picked, as CONTRIBUTING asks: the
// alternative was folding it into logon.go, which is about starting a process
// as somebody else, and this is about a process defending itself from what it
// starts.

package proc

import (
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procStringToSecurityDescriptor   = w32.Advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorDacl    = w32.Advapi32.NewProc("GetSecurityDescriptorDacl")
	procSetSecurityInfo              = w32.Advapi32.NewProc("SetSecurityInfo")
	procGetSecurityInfo              = w32.Advapi32.NewProc("GetSecurityInfo")
	procGetSecurityDescriptorControl = w32.Advapi32.NewProc("GetSecurityDescriptorControl")
	procSetTokenInformation          = w32.Advapi32.NewProc("SetTokenInformation")

	procCreateToolhelp32Snapshot = w32.Kernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First            = w32.Kernel32.NewProc("Thread32First")
	procThread32Next             = w32.Kernel32.NewProc("Thread32Next")
	procOpenThread               = w32.Kernel32.NewProc("OpenThread")
	procGetExitCodeThread        = w32.Kernel32.NewProc("GetExitCodeThread")
)

const (
	// currentProcess is the pseudo-handle every process has to itself. It is
	// never checked against a permission list, which is what lets this refuse
	// the account without refusing this process its own hand.
	currentProcess = ^uintptr(0)

	seKernelObject                   = 6
	daclSecurityInformation          = 0x4
	protectedDaclSecurityInformation = 0x80000000
	// seDaclProtected is the control bit SetSecurityInfo leaves behind when
	// it is told to protect the list, and the one thing Shielded can read
	// back to tell a shielded process from an ordinary one.
	seDaclProtected  = 0x1000
	classDefaultDacl = 6
	writeDac         = 0x40000

	snapshotOfThreads   = 0x00000004
	invalidHandle       = ^uintptr(0)
	sizeOfThreadEntry32 = 28
	errNoMoreItems      = 18
	errInvalidParameter = 87
	// Diagnostic-only rights, opened fresh rather than added to the
	// writeDac open above: widening that open's own access mask would
	// change what its own access check measures, and diagnoseThreadShutFailure
	// exists to look without doing that.
	threadQueryLimitedInformation = 0x0800
	readControl                   = 0x00020000
	ownerSecurityInformation      = 0x1
	stillActive                   = 259
	// THREADENTRY32: dwSize, cntUsage, th32ThreadID, th32OwnerProcessID, ...
	offsetOfThreadID     = 8
	offsetOfOwnerProcess = 12
)

// threadListPollStep and threadListPollWant bound the retry
// shutThreadsAlreadyRunning gives a walk that finds no thread of the named
// process. CreateToolhelp32Snapshot's own documentation warns that a
// process or thread started shortly before the snapshot is taken is not
// guaranteed to appear in it -- the same lag shutBirthConsoleHost's poll in
// console.go already accounts for on the process list, measured there at
// about 150ms for a console host to show up. A console host's threads were
// measured to lag the same snapshot further still: ShieldConhost calls this
// function the instant the host's pid is known, sometimes before the
// host's own thread has caught up to a fresh thread snapshot, and a single
// walk taken then can find none -- not because the process has none, but
// because the snapshot has not caught up. So the walk is retried, the same
// shape as the process-list poll, before shut == 0 is believed.
const (
	threadListPollStep = 25 * time.Millisecond
	threadListPollWant = 1 * time.Second
)

// selfLockingDacl builds the list Shield hands to SetSecurityInfo, and
// narrowBeforeResume in logon.go hands to the same call for a process it
// does not own yet: shut for shutOut, read-only for the OWNER RIGHTS
// identifier so the implicit owner grant does not undo the shutting, and
// full for SYSTEM and the administrators so a runaway sandbox can still be
// ended. Pulled out from Shield rather than written twice, because the two
// callers want the identical list and a second, slightly different copy of
// this text is exactly the kind of thing that drifts.
//
// The caller frees the security descriptor dacl points into once it is done
// with it; the descriptor, not the dacl pointer, is what SetSecurityInfo
// needs alive for the call and Windows needs freed afterwards.
func selfLockingDacl(shutOut string) (dacl uintptr, free func(), err error) {
	text := fmt.Sprintf("D:P(D;;GA;;;%s)(A;;RC;;;%s)(A;;GA;;;%s)(A;;GA;;;%s)",
		shutOut, sid.OwnerRights, sid.System, sid.Administrators)
	var descriptor uintptr
	if r, _, callErr := procStringToSecurityDescriptor.Call(uintptr(unsafe.Pointer(w32.UTF16(text))), 1,
		uintptr(unsafe.Pointer(&descriptor)), 0); r == 0 {
		return 0, nil, fmt.Errorf("building the list that shuts a process to %s: %w", shutOut, callErr)
	}
	var present, defaulted int32
	if r, _, callErr := procGetSecurityDescriptorDacl.Call(descriptor, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		w32.Free(descriptor)
		return 0, nil, fmt.Errorf("reading the list that shuts a process to %s: %w", shutOut, callErr)
	}
	return dacl, func() { w32.Free(descriptor) }, nil
}

// Shield closes this process to the account it is itself running as.
//
// The stub and the program it starts are the same account. The stub holds
// that account's ordinary token; the program holds one restricted from it.
// Measured before this existed: the program opened the stub with every access
// there is -- reading it, writing its memory, duplicating its handles -- and
// duplicated its token. Wearing a token of one's own user needs no privilege,
// so from there the second access check is simply gone, and the whole file
// boundary is undone from inside without one file permission being touched.
//
// A permission list cannot tell the two apart by who they are, because they
// are the same who. What it can do is refuse that who outright: a refusal
// beats a permission whatever order the list is in, and neither of the two
// processes that legitimately touch this one is affected. This process reaches
// itself through a handle that is never checked against a list, and the
// wuserbox that started it opened its handle before this ran -- a list is read
// when a handle is opened, not afterwards.
//
// Three objects, not one. The process is the obvious door. A thread is an
// object of its own with a list of its own, and one whose instructions can be
// redirected runs code inside the process that owns it -- measured, still wide
// open after the process alone had been shut. And the token's own default list
// is what a thread born later is given, so shutting only the threads that
// exist now would leave the door to be reopened by the runtime a moment after.
//
// SYSTEM and the administrators are kept throughout, so the machine can still
// end a runaway sandbox.
func Shield() error {
	me, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	// The refusal alone was not enough, and the reason is worth keeping: an
	// object's owner is granted READ_CONTROL and WRITE_DAC by Windows itself,
	// whatever the list says, so that nothing can ever be locked away from
	// whoever it belongs to. Both these processes are owned by the same
	// account, so the refusal below refused it nothing -- measured, the whole
	// way through: it opened this process for WRITE_DAC, wrote a list allowing
	// everything, took the token, wore it, and what it wore was no longer
	// restricted.
	//
	// The OWNER RIGHTS identifier is how that implicit grant is limited. Its
	// presence in a list is what switches the implicit rights off; what it is
	// given here is reading the list and nothing else, which the refusal then
	// takes back as well. What cannot be taken back is the ownership, and
	// nothing needs to be: an owner who cannot rewrite the list cannot grant
	// itself anything through it either.
	dacl, free, err := selfLockingDacl(me)
	if err != nil {
		return err
	}
	defer free()

	// The token first, so that a thread born between here and the last line
	// is born shut rather than having to be caught afterwards.
	if err := shutFutureThreads(dacl); err != nil {
		return err
	}
	if r, _, _ := procSetSecurityInfo.Call(currentProcess, seKernelObject,
		daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, dacl, 0); r != 0 {
		return fmt.Errorf("shutting this process to %s: error %d", me, r)
	}
	return shutThreadsAlreadyRunning(dacl, uint32(syscall.Getpid()))
}

// Shielded reports whether this process is carrying the list Shield installs,
// by reading the one thing about it that no privilege can talk its way past:
// whether its permission list is protected, which is to say cut off from
// anything a parent object would otherwise hand down. Windows gives a process
// its token's default list, unprotected; Shield replaces it with a protected
// one. Nothing else in a run sets that bit.
//
// Asked this way, and not by trying to open the process and seeing whether
// Windows refuses, because that answer is not about the list at all. An
// administrator holding SeDebugPrivilege opens any process whatever its list
// says, so the open-and-see test answers "not shielded" on an elevated
// machine and "shielded" on an ordinary desk, for the same shielded process.
// That is exactly how it passed here and failed on CI.
func Shielded() (bool, error) {
	var descriptor, dacl uintptr
	if r, _, _ := procGetSecurityInfo.Call(currentProcess, seKernelObject,
		daclSecurityInformation, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return false, fmt.Errorf("reading this process's own permission list: error %d", r)
	}
	defer w32.Free(descriptor)

	var control uint16
	var revision uint32
	if r, _, callErr := procGetSecurityDescriptorControl.Call(descriptor,
		uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision))); r == 0 {
		return false, fmt.Errorf("reading the control bits of this process's own descriptor: %w", callErr)
	}
	return control&seDaclProtected != 0, nil
}

// shutFutureThreads puts the list on this process's token, which is what
// Windows gives a thread created with no list of its own.
//
// Only threads. Anything else this process goes on to create takes its list
// from elsewhere -- the program started next gets its own token's default
// list, which token.AsSandbox sets, so a program that opens its own process
// by name still can. Measured, because a boundary that stopped ordinary
// programs from working would not survive contact with one.
func shutFutureThreads(dacl uintptr) error {
	var self syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(currentProcess),
		syscall.TOKEN_ADJUST_DEFAULT|syscall.TOKEN_QUERY, &self); err != nil {
		return fmt.Errorf("opening this process's own token: %w", err)
	}
	defer self.Close()
	if err := shutFutureThreadsOf(self, dacl); err != nil {
		return fmt.Errorf("shutting the threads this process has yet to make: %w", err)
	}
	return nil
}

// shutFutureThreadsOf puts the list on any token's default list, the one
// thing Windows hands a thread created with no list of its own. Split out of
// shutFutureThreads because ShieldConhost puts the identical list on a
// console host's token, reached through the one handle it holds before the
// list goes on -- a fresh open made afterwards would be refused by the very
// list it exists to apply.
func shutFutureThreadsOf(token syscall.Token, dacl uintptr) error {
	if r, _, callErr := procSetTokenInformation.Call(uintptr(token), classDefaultDacl,
		uintptr(unsafe.Pointer(&dacl)), unsafe.Sizeof(dacl)); r == 0 {
		return fmt.Errorf("setting a token's default list: %w", callErr)
	}
	return nil
}

// shutThreadsAlreadyRunning puts the same list on every thread of the named
// process it already has. Whichever process that is, its threads were made
// before any of this ran -- by this process's runtime for Shield, by the
// console host itself for ShieldConhost -- so they carry whatever list they
// were given at birth and nothing else would reach them.
//
// One thread is passed over and only one: the one that ended between being
// listed and being reached, which Windows answers with "invalid parameter"
// because the identifier now names nothing. Everything else is a failure and
// stops the run.
//
// That distinction is the whole of shutThreadsAlreadyRunningOnce's care. It
// did not draw it once: any failure to list ended the walk as though the
// list were finished, any failure to open was skipped, and the result of the
// setting was not looked at. A thread that was alive and could not be shut
// was then indistinguishable from one that had ended, and the program
// started anyway -- under a shield with a hole in it, reported as a shield.
//
// A walk that shuts nothing is retried, up to threadListPollWant, rather
// than believed on the spot: measured against ShieldConhost, calling this
// the instant a console host's pid is known can outrun the host's own
// thread catching up to a fresh Toolhelp32Snapshot, and a single walk then
// answers zero about a process that has one -- the same lag
// shutBirthConsoleHost already polls for on the process list, one level
// down. Giving up only after the ceiling keeps the "no thread found" refusal
// for what it is meant to catch: a listing that answered about somebody
// else, not a snapshot that has not caught up yet.
func shutThreadsAlreadyRunning(dacl uintptr, pid uint32) error {
	deadline := time.Now().Add(threadListPollWant)
	for {
		shut, err := shutThreadsAlreadyRunningOnce(dacl, pid)
		if err != nil {
			return err
		}
		if shut > 0 {
			return nil
		}
		if time.Now().After(deadline) {
			// A walk that shut nothing found no thread of the process it was
			// asked about, which cannot be true of a running process and
			// means the listing answered about somebody else. Better to
			// refuse than to report a shield over an empty set.
			return fmt.Errorf("no thread of process %d was found to shut", pid)
		}
		time.Sleep(threadListPollStep)
	}
}

// shutThreadsAlreadyRunningOnce is one snapshot and one walk of it -- see
// shutThreadsAlreadyRunning for why a walk that shuts nothing is retried
// rather than trusted. It reports how many threads it shut, so its caller
// can tell "none because the snapshot lagged" from "a real failure," which
// this function reports as an error instead.
func shutThreadsAlreadyRunningOnce(dacl uintptr, pid uint32) (int, error) {
	snapshot, _, callErr := procCreateToolhelp32Snapshot.Call(snapshotOfThreads, 0)
	if snapshot == 0 || snapshot == invalidHandle {
		return 0, fmt.Errorf("listing the threads of process %d: %w", pid, callErr)
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	entry := make([]byte, sizeOfThreadEntry32)
	*(*uint32)(unsafe.Pointer(&entry[0])) = sizeOfThreadEntry32
	shut := 0
	for step := procThread32First; ; step = procThread32Next {
		r, _, listErr := step.Call(snapshot, uintptr(unsafe.Pointer(&entry[0])))
		if r == 0 {
			if errors.Is(listErr, syscall.Errno(errNoMoreItems)) {
				break
			}
			return 0, fmt.Errorf("walking the threads of process %d: %w", pid, listErr)
		}
		if *(*uint32)(unsafe.Pointer(&entry[offsetOfOwnerProcess])) != pid {
			continue
		}
		id := *(*uint32)(unsafe.Pointer(&entry[offsetOfThreadID]))
		handle, _, openErr := procOpenThread.Call(writeDac, 0, uintptr(id))
		if handle == 0 {
			switch {
			case errors.Is(openErr, syscall.Errno(errInvalidParameter)):
				continue // ended while this was being written down
			case errors.Is(openErr, syscall.ERROR_ACCESS_DENIED):
				// Born shut, not missed: shutFutureThreadsOf runs before this
				// walk and puts the list on the token's default, and a
				// thread can start between that call and this one -- this
				// process's own runtime can start one of its own at any
				// point, the same reason Shield orders the token first, and
				// a console host's own startup can start one of its. Such a
				// thread already carries the list, and the refusal is the
				// proof of it rather than a guess: this account owns the
				// thread, since it owns the process it belongs to, and an
				// owner keeps implicit WRITE_DAC on Windows unless an
				// explicit list says otherwise. Nothing in this codebase
				// writes a thread's list except this walk and the
				// token-default fix that runs ahead of it, so a WRITE_DAC
				// refusal to the owner can only mean one of those two
				// already ran.
				shut++
				continue
			default:
				return 0, fmt.Errorf("opening thread %d to shut it: %w", id, openErr)
			}
		}
		r, _, _ = procSetSecurityInfo.Call(handle, seKernelObject,
			daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, dacl, 0)
		syscall.CloseHandle(syscall.Handle(handle))
		if r != 0 {
			return 0, fmt.Errorf("shutting thread %d: error %d (%s)", id, r, diagnoseThreadShutFailure(id))
		}
		shut++
	}
	return shut, nil
}

// diagnoseThreadShutFailure is called only once a shut has already failed,
// to say more than the bare error code does: whether the thread that just
// refused WRITE_DAC after granting it moments earlier is still running or
// has since ended, and whose it is. Opened fresh with only the rights each
// question needs, rather than added to shutThreadsAlreadyRunningOnce's own
// WRITE_DAC open -- widening that open's access mask would change what its
// own access check measures, and a diagnostic that changed the thing it
// was looking at would not be one. Every failure here becomes a word in the
// sentence instead of stopping it: this runs after the run has already
// failed, and a second failure while explaining the first must not hide it.
func diagnoseThreadShutFailure(id uint32) string {
	life := "cannot even query it to say whether it is still running"
	if h, _, _ := procOpenThread.Call(threadQueryLimitedInformation, 0, uintptr(id)); h != 0 {
		var code uint32
		if r, _, _ := procGetExitCodeThread.Call(h, uintptr(unsafe.Pointer(&code))); r != 0 {
			if code == stillActive {
				life = "still running"
			} else {
				life = fmt.Sprintf("already ended, exit code %d", code)
			}
		} else {
			life = "its exit code did not read either"
		}
		syscall.CloseHandle(syscall.Handle(h))
	}

	owner := "cannot even read its owner"
	if h, _, _ := procOpenThread.Call(readControl, 0, uintptr(id)); h != 0 {
		var ownerSID, descriptor uintptr
		if r, _, _ := procGetSecurityInfo.Call(h, seKernelObject, ownerSecurityInformation,
			uintptr(unsafe.Pointer(&ownerSID)), 0, 0, 0, uintptr(unsafe.Pointer(&descriptor))); r == 0 {
			if name, err := sid.Name(ownerSID); err == nil {
				owner = "owned by " + name
			} else {
				owner = "owned by an unresolvable SID"
			}
			w32.Free(descriptor)
		} else {
			owner = "its owner did not read either"
		}
		syscall.CloseHandle(syscall.Handle(h))
	}
	return life + "; " + owner
}
