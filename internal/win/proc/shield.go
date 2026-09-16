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
	"fmt"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procStringToSecurityDescriptor = w32.Advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorDacl  = w32.Advapi32.NewProc("GetSecurityDescriptorDacl")
	procSetSecurityInfo            = w32.Advapi32.NewProc("SetSecurityInfo")
	procSetTokenInformation        = w32.Advapi32.NewProc("SetTokenInformation")

	procCreateToolhelp32Snapshot = w32.Kernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First            = w32.Kernel32.NewProc("Thread32First")
	procThread32Next             = w32.Kernel32.NewProc("Thread32Next")
	procOpenThread               = w32.Kernel32.NewProc("OpenThread")
)

const (
	// currentProcess is the pseudo-handle every process has to itself. It is
	// never checked against a permission list, which is what lets this refuse
	// the account without refusing this process its own hand.
	currentProcess = ^uintptr(0)

	seKernelObject                   = 6
	daclSecurityInformation          = 0x4
	protectedDaclSecurityInformation = 0x80000000
	classDefaultDacl                 = 6
	writeDac                         = 0x40000

	snapshotOfThreads   = 0x00000004
	invalidHandle       = ^uintptr(0)
	sizeOfThreadEntry32 = 28
	// THREADENTRY32: dwSize, cntUsage, th32ThreadID, th32OwnerProcessID, ...
	offsetOfThreadID     = 8
	offsetOfOwnerProcess = 12
)

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
	text := fmt.Sprintf("D:P(D;;GA;;;%s)(A;;RC;;;%s)(A;;GA;;;%s)(A;;GA;;;%s)",
		me, sid.OwnerRights, sid.System, sid.Administrators)
	var descriptor uintptr
	if r, _, callErr := procStringToSecurityDescriptor.Call(uintptr(unsafe.Pointer(w32.UTF16(text))), 1,
		uintptr(unsafe.Pointer(&descriptor)), 0); r == 0 {
		return fmt.Errorf("building the list that shuts this process to %s: %w", me, callErr)
	}
	defer w32.Free(descriptor)

	var present, defaulted int32
	var dacl uintptr
	if r, _, callErr := procGetSecurityDescriptorDacl.Call(descriptor, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return fmt.Errorf("reading the list that shuts this process to %s: %w", me, callErr)
	}

	// The token first, so that a thread born between here and the last line
	// is born shut rather than having to be caught afterwards.
	if err := shutFutureThreads(dacl); err != nil {
		return err
	}
	if r, _, _ := procSetSecurityInfo.Call(currentProcess, seKernelObject,
		daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, dacl, 0); r != 0 {
		return fmt.Errorf("shutting this process to %s: error %d", me, r)
	}
	return shutThreadsAlreadyRunning(dacl)
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
	if r, _, callErr := procSetTokenInformation.Call(uintptr(self), classDefaultDacl,
		uintptr(unsafe.Pointer(&dacl)), unsafe.Sizeof(dacl)); r == 0 {
		return fmt.Errorf("shutting the threads this process has yet to make: %w", callErr)
	}
	return nil
}

// shutThreadsAlreadyRunning puts the same list on every thread this process
// already has. The runtime made them before any of this ran, so they carry
// the list the account was given at logon and nothing else would reach them.
//
// A thread that cannot be opened for this is passed over rather than failing
// the run: it is a thread that has ended between being listed and being
// reached, which is ordinary, and the alternative is a sandbox that refuses
// to start because a goroutine finished at the wrong moment.
func shutThreadsAlreadyRunning(dacl uintptr) error {
	snapshot, _, callErr := procCreateToolhelp32Snapshot.Call(snapshotOfThreads, 0)
	if snapshot == 0 || snapshot == invalidHandle {
		return fmt.Errorf("listing this process's own threads: %w", callErr)
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	mine := uint32(syscall.Getpid())
	entry := make([]byte, sizeOfThreadEntry32)
	*(*uint32)(unsafe.Pointer(&entry[0])) = sizeOfThreadEntry32
	for step := procThread32First; ; step = procThread32Next {
		if r, _, _ := step.Call(snapshot, uintptr(unsafe.Pointer(&entry[0]))); r == 0 {
			return nil
		}
		if *(*uint32)(unsafe.Pointer(&entry[offsetOfOwnerProcess])) != mine {
			continue
		}
		id := *(*uint32)(unsafe.Pointer(&entry[offsetOfThreadID]))
		handle, _, _ := procOpenThread.Call(writeDac, 0, uintptr(id))
		if handle == 0 {
			continue
		}
		procSetSecurityInfo.Call(handle, seKernelObject,
			daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, dacl, 0)
		syscall.CloseHandle(syscall.Handle(handle))
	}
}
