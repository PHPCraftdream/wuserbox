package proc

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procCreateJobObject    = w32.Kernel32.NewProc("CreateJobObjectW")
	procSetInformationJob  = w32.Kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJob = w32.Kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject = w32.Kernel32.NewProc("TerminateJobObject")
	procResumeThread       = w32.Kernel32.NewProc("ResumeThread")
	procTerminateProcess   = w32.Kernel32.NewProc("TerminateProcess")
)

const (
	// The child starts suspended, so it cannot start anything of its own
	// before it is in the job -- the job is what has to reach what it starts.
	//
	// It is deliberately not put in a process group of its own, which would
	// disable Ctrl+C for it entirely and take the keypress away from the
	// program it is meant for. Whether a keypress crosses into the account a
	// sandboxed program runs as is a separate question, and not one this
	// depends on: ending the job from here works either way.
	createSuspended       = 0x00000004
	createNewProcessGroup = 0x00000200

	// createNoWindow gives a process a console without putting a window on
	// the screen for it.
	//
	// Needed because CreateProcessWithLogonW starts the stub as a different
	// account, which cannot attach to the console wuserbox was started from:
	// Windows hands it a new one, and a new console comes with a window that
	// appears and takes the focus. One per run, which during a test suite is
	// several a second, and each one steals the keyboard from whoever is
	// using the machine.
	//
	// The console itself is kept rather than refused with DETACHED_PROCESS,
	// because a program that asks Windows for console handles should find
	// them: what is being taken away is the window, not the console.
	createNoWindow = 0x08000000

	// Closing the job's last handle ends every process still assigned to
	// it. That is the safety net for wuserbox itself being killed outright
	// rather than interrupted -- Windows closes this process's handles for
	// it, and one of them is the job's. Documented as requiring the
	// extended limit information class, not the basic one: setting it
	// through the basic class alone fails with ERROR_INVALID_PARAMETER,
	// measured while building this.
	jobObjectLimitKillOnJobClose    = 0x00002000
	jobObjectExtendedLimitInfoClass = 9

	// What Windows itself reports when its own Ctrl+C default handler ends a
	// process. Ending the job with this as the exit code makes a run this
	// method stopped look, to anything reading the exit code, like one a
	// keypress ended directly -- stopped, never mistaken for succeeded.
	statusControlCExit = 0xC000013A
)

// basicLimitInformation mirrors JOBOBJECT_BASIC_LIMIT_INFORMATION. Only
// limitFlags is ever set; SetInformationJobObject still reads the struct's
// full size, so every field needs to exist even unused.
type basicLimitInformation struct {
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

// ioCounters mirrors IO_COUNTERS: unused, but part of the extended limit
// information class's fixed layout, which SetInformationJobObject reads in
// full regardless of which limit is being set.
type ioCounters struct {
	readOperationCount  uint64
	writeOperationCount uint64
	otherOperationCount uint64
	readTransferCount   uint64
	writeTransferCount  uint64
	otherTransferCount  uint64
}

// extendedLimitInformation mirrors JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
// the structure JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE is documented to need.
type extendedLimitInformation struct {
	basicLimitInformation basicLimitInformation
	ioInfo                ioCounters
	processMemoryLimit    uintptr
	jobMemoryLimit        uintptr
	peakProcessMemoryUsed uintptr
	peakJobMemoryUsed     uintptr
}

// job is a job object with kill-on-close: everything the sandboxed program
// starts joins it automatically, and closing its last handle ends all of it.
type job struct {
	handle syscall.Handle
}

// newJob creates a job object with kill-on-close already set, so there is
// no window where it exists without that property.
func newJob() (*job, error) {
	r, _, callErr := procCreateJobObject.Call(0, 0)
	if r == 0 {
		return nil, fmt.Errorf("creating a job object: %w", callErr)
	}
	handle := syscall.Handle(r)

	info := extendedLimitInformation{
		basicLimitInformation: basicLimitInformation{limitFlags: jobObjectLimitKillOnJobClose},
	}
	if r, _, callErr := procSetInformationJob.Call(uintptr(handle), jobObjectExtendedLimitInfoClass,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); r == 0 {
		syscall.CloseHandle(handle)
		return nil, fmt.Errorf("setting kill-on-close on the job: %w", callErr)
	}
	return &job{handle: handle}, nil
}

// Close releases the job's handle. Kill-on-close means that if any process
// is still assigned when this runs, this is what ends it.
func (j *job) Close() {
	syscall.CloseHandle(j.handle)
}

// assign puts process in the job. It must happen while process is still
// suspended: once it is allowed to run, anything it starts before this call
// returns would not be a member and so would not be reached by the job.
func (j *job) assign(process syscall.Handle) error {
	if r, _, callErr := procAssignProcessToJob.Call(uintptr(j.handle), uintptr(process)); r == 0 {
		return fmt.Errorf("assigning the process to its job: %w", callErr)
	}
	return nil
}

// waitOrStop waits for process to end on its own, and ends the whole job if
// the caller insists.
//
// The first interrupt is left alone. It has already reached the child through
// the console, and for most of what runs in a sandbox that is the program's
// own affair: an agent stops the turn it is in the middle of, a shell clears
// its line, a REPL abandons what was typed. Ending the run there would take a
// decision away from the program that the program is better placed to make.
//
// A second one, arriving while the first is still recent, is a different
// thing: somebody is telling the run to stop and it has not. That ends the
// job, which reaches everything the child started and not only the child --
// and it still waits afterwards, so the exit code returned is the process's
// own rather than a guess made instead of reading it.
//
// It also covers the case where the keypress never reached the child at all.
// That is not hypothetical: a program running as another account may not be
// signaled by this console, and pressing twice is then the only way through.
func (j *job) waitOrStop(process syscall.Handle) (int, error) {
	interrupted := make(chan os.Signal, 2)
	signal.Notify(interrupted, os.Interrupt)
	defer signal.Stop(interrupted)

	done := make(chan error, 1)
	go func() {
		_, err := syscall.WaitForSingleObject(process, syscall.INFINITE)
		done <- err
	}()

	var first time.Time
	for {
		select {
		case <-interrupted:
			// Long enough that two presses meant as one arrive together, short
			// enough that an interrupt now and another ten minutes later are
			// two separate thoughts rather than an instruction to stop.
			const insisting = 2 * time.Second
			now := time.Now()
			if !first.IsZero() && now.Sub(first) <= insisting {
				procTerminateJobObject.Call(uintptr(j.handle), statusControlCExit)
				if err := <-done; err != nil {
					return -1, err
				}
				return finished(process), nil
			}
			first = now
		case err := <-done:
			if err != nil {
				return -1, err
			}
			return finished(process), nil
		}
	}
}

// finished reads the code a process ended with.
func finished(process syscall.Handle) int {
	var code uint32
	procGetExitCode.Call(uintptr(process), uintptr(unsafe.Pointer(&code)))
	return int(code)
}
