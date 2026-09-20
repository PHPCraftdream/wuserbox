// Package proc starts processes: sandboxed in the current console, or
// elevated through a consent prompt.
package proc

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procCreateProcessAsUser = w32.Advapi32.NewProc("CreateProcessAsUserW")
	procGetExitCode         = w32.Kernel32.NewProc("GetExitCodeProcess")
)

// Run starts a command under the given token in the caller's console, waits
// for it and returns its exit code. Standard handles are inherited, so the
// child shares the terminal.
//
// The child is put in a job object with kill-on-close before it is allowed
// to run, so nothing it starts outlives it and nothing survives wuserbox
// being killed outright. What the job does not do is take Ctrl+C away from
// the child: a keypress still reaches it through the console, because for
// most of what runs here -- an agent interrupting the turn it is in the
// middle of, a shell clearing its line, a REPL -- Ctrl+C is the program's own
// business and not a request to end the run. Insisting is what ends it; see
// waitOrStop. Relay mode is the one place the keypress cannot travel by
// attachment -- the program's console is a pseudo console the operator's
// keypress never reaches -- and there the run forwards the byte itself; see
// relayWatchInterrupts in logon.go.
func Run(token syscall.Token, commandLine, directory string) (int, error) {
	j, err := newJob()
	if err != nil {
		return -1, err
	}
	// Behind every other teardown in this function, and safe there: nothing
	// here waits on a pipe the child could keep open -- closing a handle
	// does not wait for its other holders -- so this Close always runs, and
	// promptly, with kill-on-close ending whatever the program left
	// running. RunAsAccount cannot leave its own Close in this position,
	// because its bridge finish waits for EOF on exactly the handles a
	// backgrounded child inherits; it closes its job before draining
	// instead. See P1-2 in
	// docs/reviews/release-review-P-2026-09-19-round10.md.
	defer j.Close()

	var startup syscall.StartupInfo
	var created syscall.ProcessInformation
	startup.Cb = uint32(unsafe.Sizeof(startup))
	streams, err := duplicateStandardHandles()
	if err != nil {
		return -1, err
	}
	defer streams.close()
	startup.Flags = syscall.STARTF_USESTDHANDLES
	startup.StdInput = streams.input
	startup.StdOutput = streams.output
	startup.StdErr = streams.errout
	line, err := syscall.UTF16FromString(commandLine)
	if err != nil {
		return -1, err
	}
	// Suspended only, so that nothing it starts can slip out before it is
	// assigned to the job. Deliberately not in a process group of its own:
	// that would disable Ctrl+C for it entirely, and the point is to leave the
	// keypress with the program.
	const flags = createSuspended
	r, _, callErr := procCreateProcessAsUser.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&line[0])),
		0, 0, 1, flags, 0, uintptr(unsafe.Pointer(w32.UTF16(directory))),
		uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&created)))
	if r == 0 {
		return -1, fmt.Errorf("starting %s: %w", commandLine, callErr)
	}
	return runInJob(j, &created)
}

// RunWithConsole is Run's counterpart for a program whose terminal is a
// pseudo console: pass the HPCON CreatePseudoConsole returned and the child
// is born attached to that console. GetConsoleMode answers on an attached
// console, so raw-mode terminal programs -- the ones that will not start
// against inherited pipes at all -- start, which is the problem this solves
// (see internal/sandbox/exec's takeConsoleRelay for the caller side).
//
// Standard handles are deliberately NOT duplicated and STARTF_USESTDHANDLES
// is not set: a child attached through the pseudo console attribute gets its
// console from the attachment, and bInheritHandles is passed as false, so
// nothing of the caller's handle table crosses at all. The child's
// GetStdHandle values staying invalid until it opens CONIN$/CONOUT$ itself
// is the documented CRT-startup gap, not a defect here.
//
// The job, the suspended start and the interrupt rules are Run's, shared via
// runInJob and waitOrStop. The caller keeps the pseudo console and its pipes
// open for as long as the program runs.
//
// Attachment decides Ctrl-C against the operator here. A console control
// event is delivered on the console of whoever is attached when the key is
// pressed, and the operator's keypress happens on the operator's console,
// which this child is not attached to, so the event reaches the run's own
// wiring and never the program; the run answers by forwarding the keystroke
// through the relay itself. relayWatchInterrupts in logon.go turns each
// interrupt into the raw byte 0x03 on the relay's input bridge -- what a
// real terminal's keyboard sends -- and waitOrStop's insisting escalation is
// unchanged: the first press stays the program's business, a second inside
// its window still ends the job. The console's size crosses a third,
// dedicated pipe the same relay carries: the run watches the operator's
// screen buffer and the stub's pump (internal/sandbox/exec) answers each
// change with ResizePseudoConsole, so the birth size of 80x25 holds only
// until the first measurement.
//
// The combination CreateProcessAsUserW + STARTUPINFOEX +
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE was measured live under a real sandbox
// account's restricted token, in
// docs/investigations/2026-09-20-same-window-console.md section 4.
func RunWithConsole(token syscall.Token, commandLine, directory string, pseudoConsole syscall.Handle) (int, error) {
	j, err := newJob()
	if err != nil {
		return -1, err
	}
	// Behind every other teardown in this function, and safe there: nothing
	// here waits on a pipe the child could keep open -- closing a handle
	// does not wait for its other holders -- so this Close always runs, and
	// promptly, with kill-on-close ending whatever the program left
	// running. RunAsAccount cannot leave its own Close in this position,
	// because its bridge finish waits for EOF on exactly the handles a
	// backgrounded child inherits; it closes its job before draining
	// instead. See P1-2 in
	// docs/reviews/release-review-P-2026-09-19-round10.md.
	defer j.Close()

	startup, freeStartup, err := startupInfoForPseudoConsole(pseudoConsole)
	if err != nil {
		return -1, err
	}
	defer freeStartup()
	line, err := syscall.UTF16FromString(commandLine)
	if err != nil {
		return -1, err
	}
	dir := w32.UTF16(directory)
	var created syscall.ProcessInformation
	// Suspended only, so that nothing it starts can slip out before it is
	// assigned to the job. Deliberately not in a process group of its own,
	// for the same reason Run's child is not: that would disable Ctrl+C for
	// it entirely, and the console the attachment gives it already leaves
	// the keypress with the program.
	const flags = createSuspended | extendedStartupInfoPresent
	r, _, callErr := procCreateProcessAsUser.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&line[0])),
		0, 0, 0, flags, 0, uintptr(unsafe.Pointer(dir)),
		uintptr(unsafe.Pointer(&startup.StartupInfo)), uintptr(unsafe.Pointer(&created)))
	// Every argument above reaches the call as a plain number, which is not
	// a reference the collector can see: without these, nothing stops it
	// freeing any of them while Windows is still reading them -- the same
	// reasoning as runAsAccount in logon.go.
	runtime.KeepAlive(line)
	runtime.KeepAlive(dir)
	runtime.KeepAlive(startup)
	if r == 0 {
		return -1, fmt.Errorf("starting %s: %w", commandLine, callErr)
	}
	return runInJob(j, &created)
}

// runInJob is the part of starting a child that is the same whichever way it
// was launched: into its job while still suspended, so nothing it starts can
// slip out unwatched, then running, then waited for.
func runInJob(j *job, created *syscall.ProcessInformation) (int, error) {
	defer syscall.CloseHandle(created.Process)
	defer syscall.CloseHandle(created.Thread)

	if err := j.assign(created.Process); err != nil {
		procTerminateProcess.Call(uintptr(created.Process), 1)
		return -1, err
	}
	procResumeThread.Call(uintptr(created.Thread))

	return j.waitOrStop(created.Process)
}
