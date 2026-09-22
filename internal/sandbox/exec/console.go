// Taking a console of one's own, for a program that refuses to speak through
// anything else.
//
// The bridge pipes carry bytes, and bytes are all a line-oriented program
// needs; a raw-mode terminal program checks whether its standard input is a
// real console before it will start at all, and a pipe is never one. The
// account cannot attach to the console wuserbox was started from --
// AttachConsole(ATTACH_PARENT_PROCESS) answers "access is denied", measured
// against a real sandbox account -- but it can make a console of its own:
// AllocConsole succeeds and creates a working one, GetConsoleMode and all.
// What it gets is a new, separate console window, not a share of the
// caller's, and that tradeoff is the shape of the fix rather than a
// limitation to apologize for.
//
// The relay in this file is the second answer to the same problem: a pseudo
// console, which is a console with no window at all, hosted by a conhost of
// this account's own, whose rendered bytes and keystrokes cross this process
// as plain pipe bytes -- the shape
// docs/investigations/2026-09-20-same-window-console.md measured end to end
// under a real sandbox token.

package exec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procFreeConsole           = w32.Kernel32.NewProc("FreeConsole")
	procAllocConsole          = w32.Kernel32.NewProc("AllocConsole")
	procCreatePseudoConsole   = w32.Kernel32.NewProc("CreatePseudoConsole")
	procClosePseudoConsole    = w32.Kernel32.NewProc("ClosePseudoConsole")
	procResizePseudoConsole   = w32.Kernel32.NewProc("ResizePseudoConsole")
	procSetHandleInformation  = w32.Kernel32.NewProc("SetHandleInformation")
	procGetConsoleProcessList = w32.Kernel32.NewProc("GetConsoleProcessList")
)

// The two calls that take the HPCON itself cross package vars rather than
// the procs directly. Production never reassigns them; the seam exists for
// the close tests, which need a controllable hold exactly where the native
// call sits -- a resize held between reading the handle and the call is the
// instant the close race lives in, and a close that never returns is the
// shape the drain ceiling has to bound -- and a conhost's own timing is not
// something a deterministic test can schedule around.
var (
	closePseudoConsole = func(hpc syscall.Handle) {
		procClosePseudoConsole.Call(uintptr(hpc))
	}
	resizePseudoConsole = func(hpc syscall.Handle, cols, rows int) {
		procResizePseudoConsole.Call(uintptr(hpc), coordValue(cols, rows))
	}
)

// The birth console's host shows up in the walk late -- measured about
// 150 ms after the process it hosts -- so shutBirthConsoleHost polls this
// often, for at most this long, before refusing.
const (
	birthHostPollStep = 25 * time.Millisecond
	birthHostPollWant = 3 * time.Second
	// GetConsoleProcessList is asked for this many slots: the answer is the
	// processes attached to one console, and a console is crowded long
	// before it takes 64 to hold them.
	consoleListSlots = 64
)

// getConsoleProcessList crosses a package var rather than the proc
// directly, the same way the two calls that take the HPCON itself do:
// production never reassigns it, and the seam is what lets a test stand a
// failure exactly where the native call sits -- the failure the old guard
// used to read as "no console of this process's own" and answer with a
// silent skip of the birth host's shield (review round 2, P2-1). The
// wrapper answers in Go terms: the error is non-nil exactly when the
// native call failed, which per GetConsoleProcessList's own contract is a
// zero answer -- every console has at least one process attached, so a
// successful call never returns zero -- and the errno the failure carried
// is the whole of what the call reports.
var getConsoleProcessList = func(attached []uint32) (int, error) {
	n, _, callErr := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&attached[0])),
		uintptr(len(attached)))
	if n == 0 {
		return 0, callErr
	}
	return int(n), nil
}

// shutNewConsoleHost shuts the one console host this process has gained
// since before was taken, shutting it out of shutOut -- the account SID the
// run refuses, the same who proc.Shield shuts this process to.
//
// Why the diff and not the walk alone: an HPCON is not a pid, and
// AllocConsole names no process either -- the only identity a console host
// has is parentage. Parentage alone is not enough, either, because in relay
// mode the stub's own birth console means there can be a host of this
// process's beside the new one, and filtering the walk by parent and name
// would find both and answer nothing. Only the set difference against the
// list taken before the creating call is the host that call created.
//
// Why exactly one, refused rather than guessed: a diff of zero or of several
// has no answer this code is entitled to pick. Guessing one pid among
// several would shut an innocent process and leave the real host wide open,
// and the console would be handed out all the same. So anything but exactly
// one fails the call closed: the error says the console is refused rather
// than handed out with a host left open, and whatever the creating call
// made is the caller's to close -- takeConsoleRelay closes the relay, and
// takeOwnConsole's caller ends a process whose console goes with it.
func shutNewConsoleHost(before []uint32, shutOut string) error {
	now, err := proc.ConsoleHostChildren(uint32(syscall.Getpid()))
	if err != nil {
		return fmt.Errorf("listing this process's console hosts to tell the new one: %w", err)
	}
	var fresh []uint32
	for _, pid := range now {
		if !slices.Contains(before, pid) {
			fresh = append(fresh, pid)
		}
	}
	if len(fresh) != 1 {
		return fmt.Errorf("want exactly one new console host of this process, see %d (before %v, now %v); "+
			"the console is refused rather than handed out with a host left open", len(fresh), before, now)
	}
	if err := proc.ShieldConhost(shutOut, fresh[0]); err != nil {
		return fmt.Errorf("shutting the new console host %d: %w", fresh[0], err)
	}
	return nil
}

// errorInvalidHandle is ERROR_INVALID_HANDLE, errno 6 -- the one failure
// GetConsoleProcessList is measured to answer a process with no console at
// all. The syscall package does not name this errno in the current
// toolchain, so it is restated here rather than imported, its value
// checked against Microsoft's errno table.
const errorInvalidHandle = syscall.Errno(6)

// shutBirthConsoleHost shuts the host of the console this process was born
// with, shutting it out of shutOut. The stub arrives as
// CreateProcessWithLogonW made it, and CREATE_NO_WINDOW is a console with no
// window: hosted by a conhost started for this process before any of this
// code ran, under the unrestricted token, shielded by nothing -- the third
// console host of a relay run and the only one of a plain run.
//
// GetConsoleProcessList guards the poll, because it is the one call that
// knows whether a host of this process's own is coming at all, and its
// answers are not one answer -- telling them apart is the P2-1 fix. One is
// a console of this process's own -- CREATE_NO_WINDOW's shape -- and the
// poll runs. More than one is a successful call about a console inherited
// from somebody else, which a console of this process's own never is: no
// host of this process's is coming, and the helper returns nil without
// polling. Zero is neither of those: it is a failed call, because every
// console has at least one process attached, so a successful call never
// answers zero, and GetLastError says which failure it was. The one
// failure measured to mean "no console at all" is ERROR_INVALID_HANDLE --
// a process started with DETACHED_PROCESS answers zero, error 6,
// GetConsoleWindow 0, measured on Windows 10.0.19045 on 2026-09-22 -- and
// that confirmed absence is the safe no-op the callers that arrive some
// other way than CreateProcessWithLogonW's stub legitimately produce, the
// tests' subprocesses among them. Any other failure leaves the state
// unknown, and unknown is not something this guard may spend: the error
// goes up and the run stops before the token narrows, the same refusal the
// poll's own deadline and the walk's two errors take, rather than a run
// started beside a host that was never looked for.
//
// Why a poll and not one snapshot: the host is born before this code runs
// but shows up in the walk late, and a snapshot taken at entry would answer
// "none" about a host that exists a moment later. So the walk is taken
// again every 25 ms for up to 3 s. Exactly one host is shut; more than one
// is an error; the deadline passing with none is an error too -- the run is
// refused rather than left with an unshut host.
func shutBirthConsoleHost(shutOut string) error {
	var attached [consoleListSlots]uint32
	n, err := getConsoleProcessList(attached[:])
	if err != nil {
		if errors.Is(err, errorInvalidHandle) {
			// The one failure measured to mean "no console at all":
			// nothing of this process's to shut and nothing coming.
			return nil
		}
		return fmt.Errorf("asking which console this process is attached to: %w; "+
			"the birth console's state is unknown, and the run is refused rather "+
			"than started beside a host that was never looked for", err)
	}
	// A successful call answering more than one names a console inherited
	// from somebody else -- a console of this process's own has exactly
	// this one process attached -- so there is nothing of this process's
	// to shut and nothing coming. A return value past the slots asked for
	// is the documented buffer-too-small answer, still a successful call
	// about a console this crowded can only be somebody else's.
	if n > 1 {
		return nil
	}
	// Exactly one: a console of this process's own, and the host the poll
	// below is for.
	deadline := time.Now().Add(birthHostPollWant)
	for {
		hosts, err := proc.ConsoleHostChildren(uint32(syscall.Getpid()))
		if err != nil {
			return fmt.Errorf("walking for the birth console's host: %w", err)
		}
		if len(hosts) == 1 {
			if err := proc.ShieldConhost(shutOut, hosts[0]); err != nil {
				return fmt.Errorf("shutting the birth console's host %d: %w", hosts[0], err)
			}
			return nil
		}
		if len(hosts) > 1 {
			return fmt.Errorf("this process has %d console hosts (%v) where its own birth console can have one; "+
				"the run is refused rather than left with one unshut", len(hosts), hosts)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the birth console's host never appeared within %s; "+
				"the run is refused rather than left with an unshut host", birthHostPollWant)
		}
		time.Sleep(birthHostPollStep)
	}
}

// takeOwnConsole gives this process a console of its own and points its
// standard streams at it, so the program started next inherits real console
// handles through the same STARTUPINFO duplication proc.Run already uses.
//
// The stub is born with a console attached -- CREATE_NO_WINDOW creates one
// without putting a window on it -- and AllocConsole refuses while any
// console is attached, so FreeConsole goes first. Its error is ignored on
// purpose: whatever is wrong at that point, AllocConsole fails right after
// with a reason of its own, and that is the one worth reporting.
//
// GetStdHandle is never repointed at a console AllocConsole has just made --
// the same CRT-startup gap internal/win/proc/stdin_bridge_test.go's
// fixupStdinFromConin documents -- so the console devices are opened by
// name, and a GetConsoleMode answer on each is the check that what was
// opened really is the new console rather than a failure holding a handle.
//
// The returned func puts the previous streams back. os.Exit skips deferred
// calls, so on the success path it never runs; on the error path it hands
// the streams back to the bridge pipes that reach the caller's terminal,
// where an error can actually be read.
//
// The new console's host is shut before the streams are opened, the same
// pre-Shield shut takeConsoleRelay applies to the relay's host: the host is
// born inside this function, under the unrestricted token, with Windows'
// default DACL -- the open door the review's P0-1 measured -- and
// shutNewConsoleHost is what closes it before anything else can look
// through. A failure refuses the console: the error goes back up, the stub
// stops, the process exits, and the console it had just taken goes with it
// rather than staying on with a host left open.
func takeOwnConsole(shutOut string) (func(), error) {
	procFreeConsole.Call()
	// The before-list is taken here, after FreeConsole and before
	// AllocConsole, on purpose: the console just left may have a host on its
	// way out, and the diff shutNewConsoleHost takes must count only what
	// AllocConsole adds, not what FreeConsole is still owed.
	before, err := proc.ConsoleHostChildren(uint32(syscall.Getpid()))
	if err != nil {
		return nil, fmt.Errorf("listing this process's console hosts: %w", err)
	}
	if r, _, callErr := procAllocConsole.Call(); r == 0 {
		return nil, fmt.Errorf("allocating a console of its own: %w", callErr)
	}
	if err := shutNewConsoleHost(before, shutOut); err != nil {
		return nil, err
	}
	oldStdin, oldStdout, oldStderr := os.Stdin, os.Stdout, os.Stderr
	if err := openConsoleStreams(); err != nil {
		os.Stdin, os.Stdout, os.Stderr = oldStdin, oldStdout, oldStderr
		return nil, err
	}
	// The closure is also what keeps the old *os.File values reachable until
	// the stub is done with them: a bridge writer the collector closed early
	// would end the caller's relay before the stub's last words reached it.
	return func() { os.Stdin, os.Stdout, os.Stderr = oldStdin, oldStdout, oldStderr }, nil
}

// openConsoleStreams opens CONIN$ once for input and CONOUT$ twice for
// output and error, and installs them as this process's standard streams.
// Two CONOUT$ opens rather than one handle shared between them, so that a
// program closing one of its output streams does not take the other with
// it; the C runtime's own fallback, which opens CONIN$/CONOUT$/CONERR$
// after a console it did not recognize, is the shape being copied.
func openConsoleStreams() error {
	conin, err := openConsoleDevice("CONIN$")
	if err != nil {
		return err
	}
	conout, err := openConsoleDevice("CONOUT$")
	if err != nil {
		_ = conin.Close()
		return err
	}
	conerr, err := openConsoleDevice("CONOUT$")
	if err != nil {
		_ = conin.Close()
		_ = conout.Close()
		return err
	}
	os.Stdin, os.Stdout, os.Stderr = conin, conout, conerr
	return nil
}

// openConsoleDevice opens one console device and proves it is one: a
// GetConsoleMode that answers is the difference between the new console and
// a stale handle to a console this process is no longer attached to.
func openConsoleDevice(name string) (*os.File, error) {
	device, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(device,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", name, err)
	}
	file := os.NewFile(uintptr(handle), name)
	var mode uint32
	if err := syscall.GetConsoleMode(handle, &mode); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a console: %w", name, err)
	}
	return file, nil
}

// handleFlagInherit is HANDLE_FLAG_INHERIT, the one flag noInherit is
// called for below.
const handleFlagInherit = 0x00000001

// consoleRelay is a pseudo console taken for the program, with the two pipe
// ends that carry it. Bytes written to input are the console's keystrokes;
// bytes read from output are the console's rendered output, VT and all --
// the same stream a real terminal's pixels start life as. hpc is the
// console itself, named in the child's thread attribute list by
// proc.RunWithConsole.
//
// The handle has one ownership. hpcMu is the mutex the close settles its
// transition under -- the closed state set, the handle taken out -- and the
// same mutex every resize reads before it calls; resizes counts the resize
// calls that passed the check so the close can wait them out before it
// frees the console. That makes the two WinAPI calls that consume the
// handle impossible to overlap, and it is why neither call runs under the
// mutex: a native call that wedges must wedge on its own, where finish's
// ceiling can race it, not while holding the one lock the other caller
// needs (review round 2, P1-2, coordinated with P1-1's bounded close).
type consoleRelay struct {
	hpc    syscall.Handle
	input  *os.File
	output *os.File

	hpcMu     sync.Mutex
	hpcClosed bool
	resizes   sync.WaitGroup
}

// takeConsoleRelay gives the program a console that has no window at all: a
// pseudo console, hosted by a conhost of this account's own. Unlike
// takeOwnConsole it changes nothing about this process's own standard
// streams -- the stub keeps the bridge pipes it was born with -- because the
// console is not for this process: it exists to be attached to the program
// through proc.RunWithConsole and relayed as bytes.
//
// It is called from the same pre-Shield window as takeOwnConsole, for the
// same measured reason: the console's conhost is born under the account's
// unrestricted token, and CreatePseudoConsole under the token narrowed by
// Shield is a refusal nobody has had to measure to predict. What was
// measured, docs/investigations/2026-09-20-same-window-console.md section 4,
// is the rest of it: it succeeds under the real account token, and a child
// attaches through the exact call proc.RunWithConsole makes.
//
// CreatePseudoConsole takes one input handle and one output handle and
// duplicates what it needs, so this process's own copies of those two ends
// are closed the moment the call returns -- keeping them open would be
// exactly the ambient-inheritance gap
// docs/reviews/sandbox-security-review-2026-09-19.md's P2-1 is about. The
// kept ends are stripped of HANDLE_FLAG_INHERIT for the same reason.
//
// The console is born 80 columns by 25 rows and holds that size only until
// the first resize message crosses the relay's third pipe -- the stub's own
// pumpRelayResizes answering it with ResizePseudoConsole. The relay across
// the operator bridge and the interrupt forwarding live on the run side, in
// internal/win/proc: relayInput, relayWatchInterrupts, startRelayResize.
//
// The host CreatePseudoConsole starts is shut before the relay is handed
// back. It is born in this same pre-Shield window, under the account's
// unrestricted token with Windows' default DACL -- the open door the
// review's P0-1 measured a restricted program walking through -- and the
// shut is what closes it. The shut failing refuses the whole relay: nil
// relay, error, the run goes on without a console rather than with one
// whose host is open. That is the fail-closed shape P0-1 asks for, and it
// is why the before-list of hosts is taken at the top, before anything is
// created: the before-list is what shutNewConsoleHost tells the new host
// apart from -- in relay mode this process already has its birth console's
// host beside the one about to appear. The shutOut the host is shut out of
// is handed in rather than taken here -- the same parameter
// shutNewConsoleHost applies and the same account the run's stub names
// everywhere else, computed once by the caller in the same pre-Shield
// window -- and the tests that measure the relay's bytes, pipes, resizes
// and teardown rather than the shut hand an identity nothing on the
// machine answers to, because a runner's own identity would otherwise be
// named first in the list's refusal and refuse the seat asking; the shut
// itself is measured for real by this package's account-seated wiring
// test.
func takeConsoleRelay(shutOut string) (*consoleRelay, error) {
	before, err := proc.ConsoleHostChildren(uint32(syscall.Getpid()))
	if err != nil {
		return nil, fmt.Errorf("listing this process's console hosts: %w", err)
	}
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("creating the relay's input pipe: %w", err)
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		_ = inRead.Close()
		_ = inWrite.Close()
		return nil, fmt.Errorf("creating the relay's output pipe: %w", err)
	}
	var hpc syscall.Handle
	const width, height = 80, 25
	size := coordValue(width, height)
	r, _, _ := procCreatePseudoConsole.Call(size, inRead.Fd(), outWrite.Fd(), 0, uintptr(unsafe.Pointer(&hpc)))
	// CreatePseudoConsole duplicates what it needs; this process's own
	// copies of the two ends are surplus the moment the call returns, kept
	// open or not.
	inRead.Close()
	outWrite.Close()
	if r != 0 {
		_ = inWrite.Close()
		_ = outRead.Close()
		// An HRESULT is CreatePseudoConsole's own result and the whole of
		// what it reports: unlike the BOOL-style calls elsewhere here there
		// is no error code behind it worth reaching for.
		return nil, fmt.Errorf("creating a pseudo console: hresult 0x%x", r)
	}
	relay := &consoleRelay{hpc: hpc, input: inWrite, output: outRead}
	if err := noInherit(relay.input); err != nil {
		relay.close()
		return nil, fmt.Errorf("excluding the relay's input end from inheritance: %w", err)
	}
	if err := noInherit(relay.output); err != nil {
		relay.close()
		return nil, fmt.Errorf("excluding the relay's output end from inheritance: %w", err)
	}
	// The shut before the relay is handed back. A failure closes the relay
	// -- which ends the host with the console -- and refuses it: nil relay,
	// error, the run goes on without a console rather than with one whose
	// host is open.
	if err := shutNewConsoleHost(before, shutOut); err != nil {
		relay.close()
		return nil, err
	}
	return relay, nil
}

// coordValue packs a console size into the single register the x64 calling
// convention uses for a COORD -- cols in the low 16 bits, rows in the next
// 16. It is the same packing ResizePseudoConsole takes, which is the point:
// one helper, both callers, so the birth size takeConsoleRelay hands
// CreatePseudoConsole and every later resize pumpRelayResizes hands
// ResizePseudoConsole cross the calling convention in the same shape.
func coordValue(cols, rows int) uintptr {
	return uintptr(uint32(uint16(cols)) | uint32(uint16(rows))<<16)
}

// noInherit strips HANDLE_FLAG_INHERIT from file's underlying handle -- the
// same hygiene logon.go's noInherit applies to the ends of the bridge pipes
// that stay behind: both kept relay ends stay in this process, and ambient
// inheritance is how a handle meant to stay here reaches a child it was
// never meant for.
func noInherit(file *os.File) error {
	if r, _, callErr := procSetHandleInformation.Call(file.Fd(), handleFlagInherit, 0); r == 0 {
		return callErr
	}
	return nil
}

// closeConsole ends the pseudo console and nothing else. It is its own
// method because finishing the relay needs the two ends of close separated
// in time: ending the console is what makes conhost eventually let go of
// the write end of the output pipe, and that has to happen BEFORE the read
// end is closed, while the read end closes only once the drain has been
// watched to its end -- which is finish's work, not this method's.
// ClosePseudoConsole returning is also not the completion signal for any of
// it: on Windows 11 24H2+ the call can return before the pty has finished
// draining internally, and the documented completion signal is the read
// side reaching the end of the pipe -- which is why finish keeps reading to
// EOF after calling this instead of trusting the return. Twice-safe like
// close, and twice-safe without waiting: the closed state and the handle
// are settled under hpcMu before any call is made, so a second entry finds
// nothing left to free and returns at once -- even while a first close is
// still blocked inside ClosePseudoConsole itself, which is what lets
// finish's ceiling path decline to re-enter a call that never comes back.
//
// The order inside is the P1-2 fix, and it is the review's own: the closed
// state goes first, under the mutex, which stops every resize that has not
// yet passed its check; resizes.Wait then waits out the calls that already
// passed -- each counted on its way in, each released only after its
// ResizePseudoConsole returned -- and only then is the handle freed. A
// resize in flight and the free can therefore never overlap. The mutex is
// never held across either native call, so a wedged ClosePseudoConsole
// holds nothing a resize needs, and the close runs where finish's deadline
// can race it instead of behind it.
func (r *consoleRelay) closeConsole() {
	if r == nil {
		return
	}
	r.hpcMu.Lock()
	if r.hpcClosed {
		r.hpcMu.Unlock()
		return
	}
	r.hpcClosed = true
	hpc := r.hpc
	r.hpc = 0
	r.hpcMu.Unlock()
	if hpc == 0 {
		return
	}
	r.resizes.Wait()
	closePseudoConsole(hpc)
}

// close ends the pseudo console and both pipe ends, closeConsole for the
// console and then both ends of the relay. Closing the console is also what
// ends its conhost and what lets a reader of output reach EOF -- the
// measured shape of every drain in this repository that reads a pseudo
// console's pipe. os.Exit skips deferred calls, so on the stub's success
// path close never runs; the stub's own death closes everything it names.
// Safe to call twice: the handle is cleared before it is closed, which is
// what lets a test close the relay explicitly and still have its deferred
// call find nothing left to do.
func (r *consoleRelay) close() {
	if r == nil {
		return
	}
	r.closeConsole()
	_ = r.input.Close()
	_ = r.output.Close()
}

// relayDrainCeiling is how long finish waits for the relay's output drain to
// end before giving up on it. It is a var, not a const, on purpose: the
// tests that model a wedged drain need to shrink it to keep the model
// deterministic, and nothing in production reads it before Stub runs.
// (why it exists: the exceptional path -- a drain that never ends because
// the consumer never reads and the pipe never closes; the alternative to
// giving up is a stub that hangs against a run waiting for it to die.)
var relayDrainCeiling = 5 * time.Second

// relayPump is what the tracked half of pumpRelay reports through: the
// WaitGroup the output drain is counted on, and the result of the copy that
// drain performed -- delivery's own verdict, recorded rather than discarded,
// because discarding it turned every delivery failure into a silent
// truncation.
type relayPump struct {
	drained  sync.WaitGroup
	drainErr error
}

// pumpRelay starts the two copy loops that carry the relayed console
// across this process's own standard streams -- the bridge pipes the
// run's caller duplicated its console into at this stub's birth. Rendered
// VT read from the relay's output goes out as this process writes it, and
// whatever the caller forwarded in is written to the relay's input as it
// arrives; neither loop translates, because both ends already hold the
// bytes a terminal would have sent or drawn. The input loop runs until the
// process ends and stays fire-and-forget; the output half is the tracked
// one, and the pump returned here is what finish waits on. The output
// loop's io.Copy result is recorded on the pump rather than discarded --
// discarding it, as the first draft of this code did, turned every delivery
// failure into a silent truncation behind a success exit code, the shape
// review finding P2-1 is about.
func pumpRelay(relay *consoleRelay, stdout io.Writer, stdin io.Reader) *relayPump {
	pump := &relayPump{}
	go func() {
		_, _ = io.Copy(relay.input, stdin)
	}()
	pump.drained.Add(1)
	go func() {
		defer pump.drained.Done()
		_, pump.drainErr = io.Copy(stdout, relay.output)
	}()
	return pump
}

// finish ends the relay the way the end of a run needs it ended, and the
// order is the fix, not a convention. The relay's input stops first: the
// program is dead and nothing will read a keystroke again, so the loop
// feeding them in has no work left to be right about. The console closes
// second -- closeConsole, and nothing else: ending the console is what
// makes conhost let go of the write end of the output pipe, while the read
// end stays open, because the drain still has to be watched through it. The
// drain is waited on third, and that wait is what review finding P2-1
// measured the absence of: the fixed pause the stub used to sleep narrowed
// the race between conhost's last rendered bytes and this process's exit
// without closing it, where waiting for the tracked goroutine closes it.
// The wait is exact and not merely prompt, either: io.Copy's return is
// precisely "the source is at EOF or failed AND the last Write into the
// caller's bridge has returned" -- it writes a chunk before it reads the
// next -- so a Wait on the drain is waiting for delivery, not merely for
// the pipe's end.
//
// The ceiling is the error path, not the expected one, and it is created
// here -- before the close has even begun -- because it bounds the whole
// teardown and not merely the drain: the one call in the sequence that can
// hang forever is ClosePseudoConsole, which before Windows 11 24H2 does
// not return while its output pipe has nowhere to drain (Microsoft's own
// contract), so a timer started after that call returned would never cover
// the one call that needs covering -- review finding P1-1. The close
// therefore runs on its own goroutine, and the select below races it
// against the deadline instead of standing in front of it. The expected
// path completes the moment conhost lets go of the write end, usually far
// under 250ms; the ceiling exists for the teardown that never ends --
// a close with nowhere to drain, a consumer that never reads, or both --
// and giving up there is what keeps this stub from hanging against a run
// waiting for it to die.
//
// No path re-enters a blocking close. closeConsole is twice-safe without
// waiting, so a relay.close after a verdict is either real work on the
// success path or an instant no-op; on the ceiling path nothing closes
// anything -- the goroutine already inside ClosePseudoConsole is the one
// close the console gets, the read end stays open for the same reason it
// always did (closing a handle a synchronous read is blocked in is
// undefined ground), and the stub's own death closes what it names.
//
// A non-nil return must not become a silent truncation behind the
// program's own exit code, and a verdict the drain already reached is
// never thrown away for the clock's: the drain-ended case returns the
// recorded error however the close is doing, and the ceiling case still
// takes one last non-blocking look at the drain before it reports, because
// a verdict that landed in the same instant as the deadline outranks the
// deadline. The stub returns the error, so it travels back the way every
// other late stub failure travels: reported on stderr -- a bridge pipe
// separate from the stdout one that may itself be the broken half -- and
// paid for with wuserbox's own failure exit code (exit.Failed, read back
// through exit.Of), the one signal that needs no pipe at all.
func (p *relayPump) finish(relay *consoleRelay) error {
	_ = relay.input.Close()
	waited := make(chan struct{})
	go func() {
		p.drained.Wait()
		close(waited)
	}()
	timer := time.NewTimer(relayDrainCeiling)
	defer timer.Stop()
	closed := make(chan struct{})
	go func() {
		relay.closeConsole()
		close(closed)
	}()
	select {
	case <-closed:
		// The console ended inside the budget; the drain gets what is
		// left of it. The expected path lands here: the close returns
		// in milliseconds and conhost lets go of the write end, so the
		// drain's end follows at once.
		select {
		case <-waited:
		case <-timer.C:
			return fmt.Errorf("the relay's output drain did not end within %s; the run's output may be incomplete", relayDrainCeiling)
		}
	case <-waited:
		// The drain ended first -- the pipe reached its end and its
		// last Write into the consumer returned -- while the close is
		// still going. The verdict is in, and it outranks waiting on a
		// call that may never return; relay.close below is a real close
		// of the pipe ends and an instant no-op on the console, whose
		// close finishes on its own goroutine or ends with the process.
		relay.close()
		return p.drainErr
	case <-timer.C:
		// The deadline expired before either half ended -- the shape
		// the ceiling exists for. One last non-blocking look at the
		// drain, because a verdict that landed in the same instant as
		// the deadline outranks the clock; otherwise the run is
		// reported possibly-incomplete rather than hung.
		select {
		case <-waited:
			relay.close()
			return p.drainErr
		default:
		}
		return fmt.Errorf("the relay's console close or its output drain did not end within %s; the run's output may be incomplete", relayDrainCeiling)
	}
	relay.close()
	return p.drainErr
}

// resize asks the relayed console to become cols by rows. Best effort by
// design: a refused or lost resize must not take the relay or the pump down
// -- the next message retries, and the console keeping its previous size is
// the honest visible outcome of a resize conhost would not take -- so the
// call's result is deliberately ignored. No-op on a nil relay or a closed
// one, and the closed check reads the same state under the same mutex the
// close settles its transition under -- not a separate glance at the field,
// which would leave the race P1-2 is about standing between the check and
// the call. A resize that passes the check is counted on resizes before the
// mutex is let go, and closeConsole waits that count out before it frees
// the handle, so the WinAPI call below is aimed only at a console that is
// still there and can be running only while no close is; after the closed
// state is set the call is never reached at all, which is what makes a
// resize asked for during the teardown the no-op the relay's death needs
// it to be.
func (r *consoleRelay) resize(cols, rows int) {
	if r == nil {
		return
	}
	r.hpcMu.Lock()
	if r.hpcClosed || r.hpc == 0 {
		r.hpcMu.Unlock()
		return
	}
	hpc := r.hpc
	r.resizes.Add(1)
	r.hpcMu.Unlock()
	defer r.resizes.Done()
	resizePseudoConsole(hpc, cols, rows)
}

// pumpRelayResizes starts the one loop that reads the relay's third pipe --
// the resize bridge the run built alongside the other two -- and answers
// every message by reshaping the relayed console. The stub is the only side
// that can resize the console -- the hpc lives here -- which is why the
// notification crosses as bytes at all.
//
// It is a separate pipe rather than a convention on the relay's byte
// streams, and that is deliberate: the relay's other two pipes are
// transparent byte streams, rendered VT out and keystrokes in, and an
// escape-prefixed side channel would make every keystroke a parse case --
// the same preference for explicit, separate pipes the two bridge pipes
// already embody.
//
// One message is proc.ResizeMessageLen bytes, two little-endian uint16s,
// columns then rows -- the layout encodeResize writes on the operator side;
// importing the length constant rather than restating it is what keeps the
// one wire format's two ends from drifting. A degenerate message -- columns
// or rows zero, nothing measured, nothing to ask for -- is skipped. ReadFull
// failing ends the loop: the write end closing is the run ending, the same
// shape as every drain here. Nothing waits on the loop; it runs until this
// process ends, like the two copy loops pumpRelay starts.
//
// The loop itself stays fire-and-forget, but the resizes it asks for are no
// longer bare calls: each crosses relay.resize, under the relay's single
// ownership of the HPCON, so a message answered during the teardown is a
// no-op rather than a native call aimed at a console the close has already
// freed.
func pumpRelayResizes(relay *consoleRelay, resized io.Reader) {
	go func() {
		var message [proc.ResizeMessageLen]byte
		for {
			if _, err := io.ReadFull(resized, message[:]); err != nil {
				return
			}
			cols := int(binary.LittleEndian.Uint16(message[0:]))
			rows := int(binary.LittleEndian.Uint16(message[2:]))
			if cols == 0 || rows == 0 {
				continue
			}
			relay.resize(cols, rows)
		}
	}()
}
