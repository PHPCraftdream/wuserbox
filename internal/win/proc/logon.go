package proc

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procCreateProcessWithLogon = w32.Advapi32.NewProc("CreateProcessWithLogonW")
	procSetHandleInformation   = w32.Kernel32.NewProc("SetHandleInformation")
	procSetConsoleMode         = w32.Kernel32.NewProc("SetConsoleMode")
)

const (
	// logonWithProfile loads the account's profile before the process
	// starts. Without it there is no HKEY_CURRENT_USER at all for the
	// process to write into -- measured, see
	// docs/design/an-account-of-its-own.md.
	logonWithProfile = 0x00000001
	// The environment below is built by hand rather than inherited, so it
	// has to be marked wide or Windows reads the block as the ANSI form
	// CreateProcessA callers pass.
	createUnicodeEnvironment = 0x00000400
	// local is the domain that makes CreateProcessWithLogonW look the
	// account up in this machine's own SAM rather than, on a domain-joined
	// machine, the domain the caller happens to be logged into -- where a
	// same-named account may not exist, or may be a different one.
	local = "."

	// handleFlagInherit is HANDLE_FLAG_INHERIT, the one flag
	// SetHandleInformation is called for below.
	handleFlagInherit = 0x00000001
)

// inheritedStandardHandles makes inheritable duplicates of this process's
// standard streams. CreateProcessWithLogonW has no bInheritHandles argument:
// when STARTF_USESTDHANDLES is set, the handles in STARTUPINFO must already
// be inheritable. Duplicating them avoids changing the inheritance flag on
// the caller's handles and passes exactly the three streams to the stub.
type inheritedStandardHandles struct {
	input  syscall.Handle
	output syscall.Handle
	errout syscall.Handle
}

func duplicateStandardHandles() (inheritedStandardHandles, error) {
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return inheritedStandardHandles{}, fmt.Errorf("opening the current process for standard handles: %w", err)
	}

	var out inheritedStandardHandles
	var made []syscall.Handle
	closeMade := func() {
		for _, handle := range made {
			syscall.CloseHandle(handle)
		}
	}
	duplicate := func(label string, file *os.File) (syscall.Handle, error) {
		if file == nil {
			return 0, fmt.Errorf("standard %s is nil", label)
		}
		source := syscall.Handle(file.Fd())
		if source == 0 || source == syscall.InvalidHandle {
			return 0, fmt.Errorf("standard %s is invalid", label)
		}
		var copy syscall.Handle
		if err := syscall.DuplicateHandle(current, source, current, &copy, 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
			return 0, fmt.Errorf("duplicating standard %s: %w", label, err)
		}
		made = append(made, copy)
		return copy, nil
	}

	var duplicateErr error
	if out.input, duplicateErr = duplicate("input", os.Stdin); duplicateErr != nil {
		closeMade()
		return inheritedStandardHandles{}, duplicateErr
	}
	if out.output, duplicateErr = duplicate("output", os.Stdout); duplicateErr != nil {
		closeMade()
		return inheritedStandardHandles{}, duplicateErr
	}
	if out.errout, duplicateErr = duplicate("error", os.Stderr); duplicateErr != nil {
		closeMade()
		return inheritedStandardHandles{}, duplicateErr
	}
	return out, nil
}

func (handles inheritedStandardHandles) close() {
	syscall.CloseHandle(handles.input)
	syscall.CloseHandle(handles.output)
	syscall.CloseHandle(handles.errout)
}

// outputBridge carries the account process's output back to the terminal of
// the caller. A console handle cannot be used by a process logged on as a
// different account, so the account receives pipe handles instead.
type outputBridge struct {
	stdoutRead *os.File
	stderrRead *os.File
	stdout     *os.File
	stderr     *os.File
	done       sync.WaitGroup
}

func (b *outputBridge) start() {
	if b.stdoutRead != nil {
		b.done.Add(1)
		go func() {
			defer b.done.Done()
			_, _ = io.Copy(b.stdout, b.stdoutRead)
		}()
	}
	if b.stderrRead != nil {
		b.done.Add(1)
		go func() {
			defer b.done.Done()
			_, _ = io.Copy(b.stderr, b.stderrRead)
		}()
	}
}

func (b *outputBridge) finish() {
	b.done.Wait()
	b.close()
}

func (b *outputBridge) close() {
	if b.stdoutRead != nil {
		_ = b.stdoutRead.Close()
	}
	if b.stderrRead != nil {
		_ = b.stderrRead.Close()
	}
}

// duplicateOutput replaces the console output handles with inheritable pipe
// writers and returns the reads and the original destinations for relaying.
func duplicateOutput(handles *inheritedStandardHandles) (*outputBridge, error) {
	bridge := &outputBridge{}
	if console(os.Stdout) {
		read, handle, err := bridgePipe("stdout")
		if err != nil {
			return nil, err
		}
		syscall.CloseHandle(handles.output)
		handles.output = handle
		bridge.stdoutRead = read
		bridge.stdout = os.Stdout
	}
	if console(os.Stderr) {
		read, handle, err := bridgePipe("stderr")
		if err != nil {
			bridge.close()
			return nil, err
		}
		syscall.CloseHandle(handles.errout)
		handles.errout = handle
		bridge.stderrRead = read
		bridge.stderr = os.Stderr
	}
	if bridge.stdoutRead == nil && bridge.stderrRead == nil {
		return nil, nil
	}
	return bridge, nil
}

func bridgePipe(label string) (*os.File, syscall.Handle, error) {
	read, write, err := os.Pipe()
	if err != nil {
		return nil, 0, fmt.Errorf("creating %s bridge: %w", label, err)
	}
	// Both ends of os.Pipe() are inheritable by default on Windows. read
	// stays in this process; nothing downstream of it should be able to
	// reach the write end's other half through it -- see noInherit and
	// docs/reviews/sandbox-security-review-2026-09-19.md, P2-1.
	if err := noInherit(read); err != nil {
		_ = read.Close()
		_ = write.Close()
		return nil, 0, fmt.Errorf("excluding %s bridge read end from inheritance: %w", label, err)
	}
	handle, err := duplicateInheritable(write)
	_ = write.Close()
	if err != nil {
		_ = read.Close()
		return nil, 0, fmt.Errorf("duplicating %s bridge: %w", label, err)
	}
	return read, handle, nil
}

func console(file *os.File) bool {
	if file == nil {
		return false
	}
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(file.Fd()), &mode) == nil
}

func duplicateInheritable(file *os.File) (syscall.Handle, error) {
	if file == nil {
		return 0, fmt.Errorf("pipe is nil")
	}
	source := syscall.Handle(file.Fd())
	if source == 0 || source == syscall.InvalidHandle {
		return 0, fmt.Errorf("pipe handle is invalid")
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, err
	}
	var copy syscall.Handle
	if err := syscall.DuplicateHandle(current, source, current, &copy, 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		return 0, err
	}
	return copy, nil
}

// noInherit strips HANDLE_FLAG_INHERIT from file's underlying handle. Every
// os.Pipe() end is inheritable by default on Windows, but each bridge pipe
// here has exactly one end meant to cross into the account; the other stays
// in this process and must not be reachable through ambient inheritance by
// anything else CreateProcessWithLogonW starts -- see
// docs/reviews/sandbox-security-review-2026-09-19.md, P2-1, and the same
// hygiene lock.PassTo documents for its own duplicate at
// internal/base/lock/slot.go:177-187.
func noInherit(file *os.File) error {
	handle := syscall.Handle(file.Fd())
	if r, _, callErr := procSetHandleInformation.Call(uintptr(handle), handleFlagInherit, 0); r == 0 {
		return callErr
	}
	return nil
}

// inputBridge carries the caller's real standard input into the account
// process, the input-side counterpart of outputBridge. A console handle
// cannot be read by a process logged on as a different account any more than
// it can be written to, so the account receives a pipe's read end instead,
// and the parent copies its own stdin into the write end for as long as this
// process runs.
//
// Unlike outputBridge there is nothing here to wait for: the source is a live
// interactive console, which may never give an EOF while the account process
// is still running, and stdin may reach the end of what the program inside
// wants to read from it well before that -- Run does not read anything about
// EOF from either side of a command's own execution. finish() would either
// block forever or need a spurious deadline; start() is fired and left to be
// abandoned when the whole wuserbox process ends, the accepted shape for a
// CLI wrapper's stdin-forwarding goroutine.
type inputBridge struct {
	write *os.File
	stdin *os.File
}

func (b *inputBridge) start() {
	go func() {
		_, _ = io.Copy(b.write, b.stdin)
		_ = b.write.Close()
	}()
}

// close abandons an input bridge that was built but never started -- an
// error between duplicateInput and the CreateProcessWithLogonW call below it.
// Nothing else holds b.write yet, so closing it here is safe.
func (b *inputBridge) close() {
	_ = b.write.Close()
}

// duplicateInput replaces the console input handle in handles with an
// inheritable pipe reader when standard input is a real console -- the same
// limit duplicateOutput works around for output, applied to input, which had
// none of this before: a duplicated raw console handle handed to an account
// that cannot attach to the console it names, which is what left Claude
// Code's own --print fallback the only thing the account ever saw when
// wuserbox was started from an interactive prompt with nothing piped into it.
//
// When standard input is not a console -- already redirected or piped, which
// is every non-interactive call and every existing test in this repository
// -- this returns nil, nil and handles.input is left exactly as
// duplicateStandardHandles built it: a direct duplicate of the raw handle,
// no pipe, no extra goroutine.
//
// When EnvOwnConsole is set, the stub is about to hand the program a real
// console of its own, and the bridge stands down even where stdin is a
// console: the program will not be reading this pipe, and a bridge left
// running would carry the caller's keystrokes nowhere.
//
// When EnvConsoleRelay is set the stub relays a pseudo console's bytes
// instead, and the input side of that crossing belongs to relayInput
// below: this stands down so the two can never both run, because one
// console read by two bridges would deal the caller's keystrokes out
// between them rather than deliver them.
func duplicateInput(handles *inheritedStandardHandles) (*inputBridge, error) {
	if !console(os.Stdin) || os.Getenv(EnvOwnConsole) != "" || os.Getenv(EnvConsoleRelay) != "" {
		return nil, nil
	}
	write, handle, err := inputBridgePipe()
	if err != nil {
		return nil, err
	}
	syscall.CloseHandle(handles.input)
	handles.input = handle
	return &inputBridge{write: write, stdin: os.Stdin}, nil
}

// relayInput is the input side of the console relay: when duplicateInput
// has stood down for EnvConsoleRelay, this builds the pipe the caller's
// keystrokes cross the account line on -- the same inputBridgePipe, and
// the same copy loop once the run starts it -- and the stub's pump hands
// what arrives to the pseudo console's own input pipe, the last hop
// before the program's console. Redirected standard input needs none of
// this: the stub inherits the source itself and its pump forwards it
// unchanged.
func relayInput(handles *inheritedStandardHandles) (*inputBridge, error) {
	if !console(os.Stdin) {
		return nil, nil
	}
	write, handle, err := inputBridgePipe()
	if err != nil {
		return nil, err
	}
	syscall.CloseHandle(handles.input)
	handles.input = handle
	return &inputBridge{write: write, stdin: os.Stdin}, nil
}

// inputBridgePipe creates the pipe an input bridge threads the caller's
// console input through: the read end crosses into the account, duplicated
// inheritable the same way bridgePipe duplicates an output pipe's write end;
// the write end stays here, stripped of inheritance for the same reason
// bridgePipe strips its own read end -- see noInherit.
func inputBridgePipe() (*os.File, syscall.Handle, error) {
	read, write, err := os.Pipe()
	if err != nil {
		return nil, 0, fmt.Errorf("creating stdin bridge: %w", err)
	}
	if err := noInherit(write); err != nil {
		_ = read.Close()
		_ = write.Close()
		return nil, 0, fmt.Errorf("excluding stdin bridge write end from inheritance: %w", err)
	}
	handle, err := duplicateInheritable(read)
	_ = read.Close()
	if err != nil {
		_ = write.Close()
		return nil, 0, fmt.Errorf("duplicating stdin bridge: %w", err)
	}
	return write, handle, nil
}

// Console mode bits. ENABLE_LINE_INPUT and ENABLE_ECHO_INPUT are the
// console's own line editor, which collects a line, echoes it and hands it
// over only on Enter -- the opposite of what a relayed terminal wants,
// where each keystroke leaves for the bridge as it is typed.
// ENABLE_VIRTUAL_TERMINAL_INPUT reports the special keys as the VT
// sequences a terminal would have sent. ENABLE_VIRTUAL_TERMINAL_PROCESSING
// makes the console act on the VT it is given rather than print it raw; it
// wears the same number as ENABLE_ECHO_INPUT because the two name bits of
// different mode words.
const (
	enableLineInput                 = 0x00000002
	enableEchoInput                 = 0x00000004
	enableVirtualTerminalInput      = 0x00000200
	enableVirtualTerminalProcessing = 0x00000004
)

// relayConsoleModes puts the operator's own console into the shape a
// relayed terminal needs and returns the call that puts it back. Input
// loses its line editor -- line input and echo off, so a keystroke
// reaches the bridge as it is typed, unbuffered and unechoed -- and gains
// VT input, so the special keys arrive as sequences rather than scan
// codes. Output gains VT processing, because what the relay delivers is
// already rendered VT and the console is the thing that has to act on it.
// ENABLE_PROCESSED_INPUT is deliberately left as it was: Ctrl-C stays the
// run's own interrupt in this mode too, raised on this process and
// answered by waitOrStop exactly as ever, and whether the keystroke should
// also travel into the relay as a byte is the next task's question, not
// this one's.
//
// The restore runs on every ordinary return, success and error both; a
// panic or a kill skips it, and making the mode survive those is later
// work, not an oversight here.
func relayConsoleModes() (func(), error) {
	type savedMode struct {
		handle syscall.Handle
		mode   uint32
	}
	var saved []savedMode
	restore := func() {
		for _, m := range saved {
			procSetConsoleMode.Call(uintptr(m.handle), uintptr(m.mode))
		}
	}
	if console(os.Stdin) {
		handle := syscall.Handle(os.Stdin.Fd())
		var mode uint32
		if err := syscall.GetConsoleMode(handle, &mode); err != nil {
			restore()
			return nil, fmt.Errorf("reading standard input's console mode: %w", err)
		}
		relay := mode&^(enableLineInput|enableEchoInput) | enableVirtualTerminalInput
		if r, _, callErr := procSetConsoleMode.Call(uintptr(handle), uintptr(relay)); r == 0 {
			restore()
			return nil, fmt.Errorf("setting standard input's console mode for the relay: %w", callErr)
		}
		saved = append(saved, savedMode{handle: handle, mode: mode})
	}
	if console(os.Stdout) {
		handle := syscall.Handle(os.Stdout.Fd())
		var mode uint32
		if err := syscall.GetConsoleMode(handle, &mode); err != nil {
			restore()
			return nil, fmt.Errorf("reading standard output's console mode: %w", err)
		}
		if r, _, callErr := procSetConsoleMode.Call(uintptr(handle), uintptr(mode|enableVirtualTerminalProcessing)); r == 0 {
			restore()
			return nil, fmt.Errorf("setting standard output's console mode for the relay: %w", callErr)
		}
		saved = append(saved, savedMode{handle: handle, mode: mode})
	}
	return restore, nil
}

// EnvOwnConsole is how a run tells the stub that the program should get a
// console of its own rather than the caller's piped-around one. It is set by
// the --own-console run flag the same way EnvNonInteractive is set by
// --non-interactive, read by the stub in internal/sandbox/exec, and unset
// there before the program starts, so nothing inside the sandbox ever sees
// it. duplicateInput reads it on this side: with a console of its own coming,
// a bridge that copies the caller's keystrokes into a pipe nobody reads
// anymore would only swallow them.
const EnvOwnConsole = "WUSERBOX_OWN_CONSOLE"

// EnvConsoleRelay is EnvOwnConsole's counterpart for the other mechanism: a
// pseudo console the stub takes and the program is attached to, with no
// window of its own, whose rendered bytes reach the caller as pipe bytes
// rather than as a second window on the desktop. Set by a run the same way,
// read and unset by the stub before the program starts, so nothing inside
// the sandbox ever sees it.
const EnvConsoleRelay = "WUSERBOX_CONSOLE_RELAY"

// RunAsAccount starts commandLine logged on as a local account, in the same
// job object and with the same interrupt handling as Run, but through
// CreateProcessWithLogonW rather than a token this process already holds.
//
// That is the one launch call documented to succeed from an ordinary user
// account without SE_TCB_NAME or "act as part of the operating system" --
// measured, see docs/design/an-account-of-its-own.md -- which is why
// starting a sandbox's own account needs no administrator rights on every
// run, only on init, the same as starting one under a restricted copy of
// the caller's own token used to.
//
// env replaces whatever this process would otherwise hand the child, rather
// than letting it inherit wuserbox's own variables and overriding a few of
// them afterwards, which would leave everything not overridden pointing at
// the caller's environment still.
//
// The child it starts is a stub of wuserbox's own, and from the moment
// CreateProcessWithLogonW below returns until that stub's own code reaches
// proc.Shield it is wide open: the account's unrestricted token, and
// Windows' own default security descriptor, which grants that same account
// full access to both the process and its one thread. A process already
// running as the account -- a second concurrent run of the same sandbox --
// can open either one and put code inside, which is the measured mechanism:
// a restricted process wearing a token of its own user is answered with
// identification level, which opens nothing, while THREAD_SET_CONTEXT on a
// thread runs whatever the attacker likes inside a process still holding the
// unrestricted token -- see
// docs/investigations/the-window-before-the-shield.md. narrowBeforeResume
// below narrows that window; it cannot close it, and says why where it
// lives.
//
// Closing is not the narrowing's job, and cannot be: the window closes
// because a stub is never being born while a program of the same sandbox is
// alive. Holding that true is the caller's lease and not this function's:
// the slot -- one exclusive file handle named for the sandbox's group -- is
// taken by the command that owns the run, from before anything changes the
// state two runs share until the run is entirely over. It lived here once,
// taken at the logon and released when the job closed, and that placement
// was measured defending too little: a second run filled -- cleared,
// forgot, recopied -- the shared profile on its way to being refused,
// because a run's reach is wider than its launch and only the command layer
// knows how wide. See holdSlot in internal/cli/setup; the design is
// docs/design/one-stub-for-a-sandbox.md with n = 1, serialize whole runs.
func RunAsAccount(username, password, commandLine, directory string, env []string) (int, error) {
	return runAsAccount(username, password, commandLine, directory, env, "", "")
}

// RunAsAccountWithLease transfers the sandbox's lease into the suspended stub
// before it can execute. The stub adopts and holds the duplicate; the program
// is handed nothing. The slot can be granted before the chain's last process
// object signals -- a process releases its handles before its object signals,
// so that ordering is a tautology of handle release, not a defect (measured;
// see TestTheProgramCannotRunWhenTheSlotIsGranted) -- and what the guarantee
// buys is that at the grant the program is down to its exit's reaper thread,
// which never returns to user mode, measured 8 runs out of 8. The stub, the
// trusted and shielded process, remains the holder the guarantee rests on.
func RunAsAccountWithLease(username, password, commandLine, directory string, env []string, slotPath string) (int, error) {
	if slotPath == "" {
		return -1, fmt.Errorf("the sandbox slot path is empty")
	}
	transferPath, cleanup, err := lock.PrepareTransfer(slotPath)
	if err != nil {
		return -1, err
	}
	defer cleanup()
	filtered := make([]string, 0, len(env)+1)
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if ok && strings.EqualFold(key, lock.TransferEnv) {
			continue
		}
		filtered = append(filtered, entry)
	}
	filtered = append(filtered, lock.TransferEnv+"="+transferPath)
	return runAsAccount(username, password, commandLine, directory, filtered, slotPath, transferPath)
}

func runAsAccount(username, password, commandLine, directory string, env []string, slotPath, transferPath string) (int, error) {
	accountSID, err := sid.Lookup(username)
	if err != nil {
		return -1, fmt.Errorf("looking up %s to narrow its own stub before it runs: %w", username, err)
	}
	// Read once, here, where every relay-mode decision below reads it: the
	// stub reads the same variable in its own birth window, and the two
	// halves of the relay -- its console inside the account, this side's
	// modes and pipes out here -- agree because both were set by the same
	// run.
	relayMode := os.Getenv(EnvConsoleRelay) != ""
	j, err := newJob()
	if err != nil {
		return -1, err
	}
	jobClosed := false
	// endJob tears the job -- and with kill-on-close set, every process
	// still assigned to it -- down exactly once. The deferred call stands
	// behind every return the run makes before its program has been waited
	// for; the explicit one after waitOrStop below is the earlier of the
	// two, and that ordering is the whole fix. Defers run in reverse, so
	// before the reorder the bridge's finish -- registered after this Close
	// -- ran first, and finish waits for EOF on the bridge pipes, which
	// arrives only once every holder of an inherited write end is gone. A
	// program that backgrounds a child before exiting -- the ordinary shell
	// idiom -- leaves that child holding one; the Close that would end it
	// stood behind the wait that needed it dead, so the run stood in
	// done.Wait() forever: exit code lost, slot leased, sandbox looking
	// hung. Closing the job first ends the leftover child, the pipes reach
	// EOF, and the drain that follows has nothing left to wait for. See
	// P1-2 in docs/reviews/release-review-P-2026-09-19-round10.md.
	endJob := func() {
		if jobClosed {
			return
		}
		jobClosed = true
		j.Close()
	}
	defer endJob()

	var startup syscall.StartupInfo
	var created syscall.ProcessInformation
	startup.Cb = uint32(unsafe.Sizeof(startup))
	streams, err := duplicateStandardHandles()
	if err != nil {
		return -1, err
	}
	bridge, err := duplicateOutput(&streams)
	if err != nil {
		streams.close()
		return -1, err
	}
	input, err := duplicateInput(&streams)
	if err != nil {
		streams.close()
		if bridge != nil {
			bridge.close()
		}
		return -1, err
	}
	if relayMode {
		// duplicateInput stood down for the relay; the relay's own input
		// pipe is what the caller's keystrokes cross on instead. See
		// relayInput.
		input, err = relayInput(&streams)
		if err != nil {
			streams.close()
			if bridge != nil {
				bridge.close()
			}
			return -1, err
		}
	}
	streamsClosed := false
	closeStreams := func() {
		if !streamsClosed {
			streams.close()
			streamsClosed = true
		}
	}
	defer closeStreams()
	bridgeStarted := false
	defer func() {
		if bridge == nil {
			return
		}
		if bridgeStarted {
			bridge.finish()
			return
		}
		bridge.close()
	}()
	inputStarted := false
	defer func() {
		if input == nil {
			return
		}
		if !inputStarted {
			input.close()
		}
	}()
	startup.Flags = syscall.STARTF_USESTDHANDLES
	startup.StdInput = streams.input
	startup.StdOutput = streams.output
	startup.StdErr = streams.errout
	line, err := syscall.UTF16FromString(commandLine)
	if err != nil {
		return -1, err
	}
	block, err := environmentBlock(env)
	if err != nil {
		return -1, err
	}
	secret, err := syscall.UTF16FromString(password)
	if err != nil {
		return -1, err
	}
	// The password has to exist in memory in the form Windows reads, and
	// this is the only copy wuserbox makes of it. Cleared the moment the
	// call is done with it rather than left for the collector, which would
	// leave it lying in a freed page for as long as that page went unused.
	defer clear(secret)

	user, domain, cwd := w32.UTF16(username), w32.UTF16(local), w32.UTF16(directory)
	if relayMode {
		// The operator's own console serves the relay for the run's
		// duration and comes back out of it on every ordinary return --
		// success and error both, the defers being what carries the
		// restore; a panic or a kill is the gap later work owes.
		restoreConsole, err := relayConsoleModes()
		if err != nil {
			return -1, err
		}
		defer restoreConsole()
	}
	// Suspended, for the same reason Run starts its own child suspended:
	// nothing it starts can slip out before it is assigned to the job.
	//
	// And without a window: see createNoWindow. The stub cannot share the
	// console wuserbox was started from -- a different account cannot attach
	// to it, for input any more than for output -- so console output is
	// carried back through outputBridge and console input is carried across
	// through inputBridge instead.
	const flags = createSuspended | createUnicodeEnvironment | createNoWindow
	r, _, callErr := procCreateProcessWithLogon.Call(
		uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(&secret[0])), logonWithProfile,
		0, uintptr(unsafe.Pointer(&line[0])),
		flags, uintptr(unsafe.Pointer(&block[0])), uintptr(unsafe.Pointer(cwd)),
		uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&created)))
	// Every argument above reaches the call as a plain number, which is not
	// a reference the collector can see: without this, nothing stops it
	// freeing any of them while Windows is still reading them.
	runtime.KeepAlive(user)
	runtime.KeepAlive(domain)
	runtime.KeepAlive(cwd)
	runtime.KeepAlive(secret)
	runtime.KeepAlive(line)
	runtime.KeepAlive(block)
	// The parent copies output from the pipe readers while the account process
	// runs. Its copies of the inheritable writer handles must be closed now, or
	// the readers could never observe EOF when the child exits.
	closeStreams()
	if r == 0 {
		return -1, fmt.Errorf("starting %s as %s: %w", commandLine, username, callErr)
	}
	if bridge != nil {
		bridge.start()
		bridgeStarted = true
	}
	if input != nil {
		input.start()
		inputStarted = true
	}
	defer syscall.CloseHandle(created.Process)
	defer syscall.CloseHandle(created.Thread)

	if err := j.assign(created.Process); err != nil {
		procTerminateProcess.Call(uintptr(created.Process), 1)
		return -1, err
	}
	if slotPath != "" {
		if err := lock.PassTo(slotPath, created.Process, transferPath); err != nil {
			procTerminateProcess.Call(uintptr(created.Process), 1)
			return -1, err
		}
	}
	// Before ResumeThread and not after: the stub has not executed one
	// instruction of its own yet, so this is the earliest anything in this
	// process can act on what CreateProcessWithLogonW just made.
	if err := narrowBeforeResume(created.Process, accountSID.String()); err != nil {
		procTerminateProcess.Call(uintptr(created.Process), 1)
		return -1, err
	}
	procResumeThread.Call(uintptr(created.Thread))

	// The exit code is already in hand -- waitOrStop reads it before
	// returning -- so tearing the job down now, with everything the program
	// left running still inside it, costs nothing and is what unblocks the
	// bridge drain waiting further down in the defers. See endJob above.
	code, err := j.waitOrStop(created.Process)
	endJob()
	return code, err
}

// environmentBlock turns a list of "NAME=VALUE" strings into the
// double-NUL-terminated wide block CREATE_UNICODE_ENVIRONMENT expects: each
// entry NUL-terminated in turn, the whole block closed by one more NUL.
func environmentBlock(env []string) ([]uint16, error) {
	if len(env) == 0 {
		return []uint16{0, 0}, nil
	}
	var block []uint16
	for _, entry := range env {
		encoded, err := syscall.UTF16FromString(entry)
		if err != nil {
			return nil, fmt.Errorf("encoding the environment entry %q: %w", entry, err)
		}
		block = append(block, encoded...) // UTF16FromString already NUL-terminates entry
	}
	return append(block, 0), nil
}

// narrowBeforeResume gives the still-suspended stub process the same shut
// list proc.Shield gives it from inside -- applied here, by the parent,
// before the child has run a single instruction of its own, rather than
// however far into Go's own runtime start-up and argument parsing the child
// gets before it reaches Shield itself.
//
// It cannot close the window Shield exists to close, only narrow it. The
// process object already exists, carrying Windows' own default security
// descriptor -- which comes from the new token's own default DACL and grants
// the account full access -- from the moment CreateProcessWithLogonW
// returns, which is before this function is ever called. A process already
// running as the account could in principle open it in the gap between that
// return and the SetSecurityInfo call below completing; nothing in an
// unprivileged process can make that gap zero. What narrowing buys is real
// and worth having anyway: without it the window is as wide as everything
// the child does before reaching Shield, easily milliseconds of Go runtime
// start-up and flag parsing; with it, the window is the width of one
// syscall, run in the parent, against an object the child has not yet been
// allowed to touch.
//
// The thread and the token's own default DACL are deliberately left alone,
// and that is not an oversight -- measured, by the test this function was
// built to pass: narrowing either one broke every real run. Shield's own
// thread narrowing reopens each of the stub's threads by a fresh OpenThread,
// which -- unlike the process, shut and reopened through the pseudo-handle
// every process has to itself, checked against no list at all -- is a real,
// listed handle open and refused once the same identity has already been
// denied it. Shut the thread here and Shield can no longer shut it again
// from inside; shut the token's default DACL here and every thread the Go
// runtime starts before Shield runs -- there is more than one -- inherits
// that same already-denied list and hits the same wall. So this narrows only
// what Shield reopens through a check-free handle, and leaves the rest of
// the window, thread and future threads both, exactly as wide as it was:
// closed by Shield, same as today, once the stub's own code reaches it.
func narrowBeforeResume(process syscall.Handle, accountSID string) error {
	dacl, free, err := selfLockingDacl(accountSID)
	if err != nil {
		return err
	}
	defer free()

	if r, _, _ := procSetSecurityInfo.Call(uintptr(process), seKernelObject,
		daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, dacl, 0); r != 0 {
		return fmt.Errorf("narrowing %s's stub process before resuming it: error %d", accountSID, r)
	}
	return nil
}
