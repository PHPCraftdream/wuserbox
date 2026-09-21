// The console hosts a process leaves behind, and shutting one to the account
// it runs as. A pseudo console is not the process that serves it: an HPCON
// names a console, and the conhost.exe behind it is an ordinary process this
// one started under its own unrestricted token -- a door Shield cannot see,
// because Shield shuts the process it runs in, and the host is not that
// process. This file is about the other one: finding it by the one thing
// that connects it, parentage, and shutting it with the same list Shield
// uses, which is why it sits beside shield.go rather than inside it.

package proc

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	// procOpenAnotherProcess is OpenProcess under a second name because the
	// prowler's test file already declares procOpenProcess, and two LazyProcs
	// for one entry point cannot share a package.
	procOpenAnotherProcess = w32.Kernel32.NewProc("OpenProcess")
	procProcess32First     = w32.Kernel32.NewProc("Process32FirstW")
	procProcess32Next      = w32.Kernel32.NewProc("Process32NextW")
)

const (
	snapshotOfProcesses = 0x00000002 // TH32CS_SNAPPROCESS
	// processQueryLimited is PROCESS_QUERY_LIMITED_INFORMATION, asked for
	// beside WRITE_DAC because the host's token is read through the same
	// handle -- ShieldConhost holds one handle for everything it does, and
	// cannot go back for the token by name once the list is on.
	processQueryLimited = 0x1000
)

// processEntry32 mirrors PROCESSENTRY32W. Go's natural layout matches the C
// one on windows/amd64 field for field -- the only padding either compiler
// adds is the four bytes after th32ProcessID that put the pointer-sized
// th32DefaultHeapID on its own alignment -- so the struct is handed to the
// walk calls as it is laid out here.
type processEntry32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

// ConsoleHostChildren lists the conhost.exe processes whose parent is pid --
// the console hosts pid has started, however it started them.
//
// An HPCON names the console, not the host, so this walk is how the host is
// found before it can be shut, and parentage is the only thread connecting
// it back. Measured live on Windows 10.0.19045 by a probe run on
// 2026-09-21: the conhost CreatePseudoConsole spawns is a child of the
// caller, with a command line like `\??\C:\WINDOWS\system32\conhost.exe
// --headless --width 80 --height 25 --signal 0x... --server 0x...`; the
// conhost AllocConsole spawns is a child of the caller too
// (`\??\C:\WINDOWS\system32\conhost.exe 0x4`); the conhost a CREATE_NO_WINDOW
// process gets is parented to that process itself and appears
// asynchronously, about 150 ms after its birth; and a process that merely
// inherits a console spawns none.
//
// An empty list is a result, not an error: whether pid should have a console
// host is the caller's business, and the walk cannot know what the list
// means.
func ConsoleHostChildren(pid uint32) ([]uint32, error) {
	snapshot, _, callErr := procCreateToolhelp32Snapshot.Call(snapshotOfProcesses, 0)
	if snapshot == 0 || snapshot == invalidHandle {
		return nil, fmt.Errorf("listing the processes to look for console hosts: %w", callErr)
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	// The walk ends and fails with the same answer, zero; only the error
	// Windows leaves behind tells them apart, and 18 -- ERROR_NO_MORE_FILES,
	// errNoMoreItems -- is the one that means the end. Anything else stops
	// the run, the same distinction shutThreadsAlreadyRunning draws.
	var hosts []uint32
	entry := processEntry32{}
	for step := procProcess32First; ; step = procProcess32Next {
		entry.dwSize = uint32(unsafe.Sizeof(entry))
		r, _, listErr := step.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if r == 0 {
			if errors.Is(listErr, syscall.Errno(errNoMoreItems)) {
				break
			}
			return nil, fmt.Errorf("walking the process list: %w", listErr)
		}
		if entry.th32ParentProcessID == pid &&
			strings.EqualFold(syscall.UTF16ToString(entry.szExeFile[:]), "conhost.exe") {
			hosts = append(hosts, entry.th32ProcessID)
		}
	}
	return hosts, nil
}

// ShieldConhost shuts a console host this process created, the way Shield
// shuts this process itself: all three objects of it, not the process alone.
// A thread whose instructions get redirected runs code inside the host
// whatever the process list says, and a thread born after the walk would
// carry the token's default list, which grants the account everything -- so
// the list goes on the host's token first, on the host second, and on every
// thread it already has last. That is not a theory about conhost: measured,
// a restricted caller opened it PROCESS_ALL_ACCESS and ran
// CreateRemoteThread(GetCurrentProcessId) inside it, execution in an
// unrestricted address space (docs/reviews/security-performance-review-2026-09-20.md,
// P0-1). What Shield gives itself, the host gets.
//
// The account is named rather than looked up because the host runs as the
// caller's own account, but the caller is the one who says who to refuse
// from outside -- the same shape narrowBeforeResume takes, so a sandbox that
// has not restricted itself yet can still narrow what it is about to leave
// behind.
//
// Everything is done through the one handle taken below, and that order is
// load-bearing. Once the process list is on, the account the host runs as
// can open nothing of it by name anymore: a fresh open made after that would
// be refused by the very list this function exists to apply. The token is
// read through this handle, and the threads are reached through fresh
// OpenThread calls made before their own doors close -- each thread still
// carries the list it was born with until the walk writes over it, and the
// token is shut first so a thread born in between is born shut, the same
// ordering Shield itself uses.
func ShieldConhost(accountSID string, pid uint32) error {
	dacl, free, err := selfLockingDacl(accountSID)
	if err != nil {
		return err
	}
	defer free()

	host, _, openErr := procOpenAnotherProcess.Call(writeDac|processQueryLimited, 0, uintptr(pid))
	if host == 0 {
		return fmt.Errorf("opening console host %d to shut it: %w", pid, openErr)
	}
	defer syscall.CloseHandle(syscall.Handle(host))

	var token syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(host),
		syscall.TOKEN_ADJUST_DEFAULT|syscall.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("opening console host %d's token: %w", pid, err)
	}
	defer token.Close()
	// The token first, so that a thread born between here and the last line
	// is born shut rather than having to be caught afterwards.
	if err := shutFutureThreadsOf(token, dacl); err != nil {
		return fmt.Errorf("shutting console host %d's threads it has yet to make: %w", pid, err)
	}
	if r, _, _ := procSetSecurityInfo.Call(host, seKernelObject,
		daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, dacl, 0); r != 0 {
		return fmt.Errorf("shutting console host %d: error %d", pid, r)
	}
	return shutThreadsAlreadyRunning(dacl, pid)
}
