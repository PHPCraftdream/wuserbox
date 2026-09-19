// The teardown P1-2 is about, measured on the whole real chain: a run
// through RunAsAccountWithLease whose program leaves a backgrounded child
// holding an inherited copy of the output bridge's write end, and which has
// to come back anyway -- promptly, with the program's own exit code, the
// child killed by the job, and the slot free for the next run.
//
// The output bridge only exists when the caller's own stdout is a console --
// that is the condition duplicateOutput builds it under, and a pipe, which
// is what every other test here substitutes for the console, never satisfies
// it. So this test re-execs itself attached to a Windows pseudo console, the
// same stand-in the proc package's stdin_bridge_test.go uses for real
// console input, pointed at CONOUT$ this time: inside that child,
// GetConsoleMode answers for the output handle exactly as it would in an
// interactive prompt, and the run the child makes builds the bridge a real
// interactive run builds.
//
// It needs administrator rights and skips without them, like every test
// that builds a real account. This puts internal/e2e at thirteen entries
// where the layout rules ask for about seven. Named rather than quietly
// picked, as CONTRIBUTING asks: it shares the account fixture with the
// account tests and the pseudo-console trick with a file in another
// package, and the one thing this file is about -- a run that must end while
// something it started is still holding its output -- is neither a streams
// question nor a slot one.

package e2e

import (
	"fmt"
	"os"
	goexec "os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/exec"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

const (
	teardownRunnerFlag       = "-wuserbox-teardown-runner"
	teardownBackgrounderFlag = "-wuserbox-teardown-backgrounder"
	teardownSlouchFlag       = "-wuserbox-teardown-slouch"

	// Kept far from any code a real program would end on, for the reason
	// slotVictimBroke keeps its distance: a stand-in that failed on its own
	// must never read as the exit code it is standing in for.
	teardownBroke = 1 << 24

	// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE and EXTENDED_STARTUPINFO_PRESENT,
	// spelled out because x/sys is a dependency this project does not take.
	teardownPseudoConsoleAttribute = 0x00020016
	teardownExtendedStartupInfo    = 0x00080000
)

var (
	procTeardownCreatePseudoConsole = w32.Kernel32.NewProc("CreatePseudoConsole")
	procTeardownClosePseudoConsole  = w32.Kernel32.NewProc("ClosePseudoConsole")
	procTeardownInitAttrList        = w32.Kernel32.NewProc("InitializeProcThreadAttributeList")
	procTeardownUpdateAttr          = w32.Kernel32.NewProc("UpdateProcThreadAttribute")
	procTeardownDeleteAttrList      = w32.Kernel32.NewProc("DeleteProcThreadAttributeList")
	procTeardownCreateProcess       = w32.Kernel32.NewProc("CreateProcessW")
	procTeardownTerminate           = w32.Kernel32.NewProc("TerminateProcess")
	procTeardownGetExitCode         = w32.Kernel32.NewProc("GetExitCodeProcess")
	procTeardownOpenProcess         = w32.Kernel32.NewProc("OpenProcess")
	procTeardownWait                = w32.Kernel32.NewProc("WaitForSingleObject")
)

// teardownStartupInfoEx mirrors STARTUPINFOEXW: a plain STARTUPINFOW
// followed by the attribute-list pointer CreateProcessW reads when
// EXTENDED_STARTUPINFO_PRESENT is set -- the same shape the proc package's
// own pseudo-console test carries, unexported there and so not reusable
// here.
type teardownStartupInfoEx struct {
	syscall.StartupInfo
	attributeList uintptr
}

// TestARunComesBackWhenItsProgramLeavesAChildHoldingTheOutput is the
// regression for P1-2 of
// docs/reviews/release-review-P-2026-09-19-round10.md, on the real chain and
// under the real bridge: the program runs through the stub as the sandbox's
// own restricted self, its output crosses a logon boundary through the
// bridge pipes, and it leaves a backgrounded child holding an inherited
// write end when it goes. The run owes the operator four things afterwards,
// and each is measured here: it comes back at all -- a run parked forever in
// the bridge drain is what the finding described, and the bound below is
// what turns that from a hung suite into this test's failure; it comes back
// with the program's own exit code, not a loss; the leftover child is dead,
// killed by the job whose close the reorder moved ahead of the drain; and
// the slot is free for the next run the moment the command layer's release
// runs.
func TestARunComesBackWhenItsProgramLeavesAChildHoldingTheOutput(t *testing.T) {
	requireAdministrator(t)
	// The lock files land here, in this test's own state directory, the way
	// lease_test points its commands at one.
	t.Setenv("LOCALAPPDATA", stateDir(t))
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	stub := stubBinary(t, root)
	box := newRealBox(t, firstSandbox, root)
	box.hand(t, root, grant.RW)

	pidFile := filepath.Join(root, "leftover.pid")
	resultFile := filepath.Join(root, "runner.txt")

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runnerLine := syscall.EscapeArg(exe) + " " + teardownRunnerFlag + " " +
		syscall.EscapeArg(resultFile) + " " + syscall.EscapeArg(box.group) + " " +
		syscall.EscapeArg(box.sid) + " " + syscall.EscapeArg(box.account) + " " +
		syscall.EscapeArg(box.password) + " " + syscall.EscapeArg(stub) + " " +
		syscall.EscapeArg(root) + " " + syscall.EscapeArg(pidFile)

	code, cameBack := insideAPseudoConsole(t, runnerLine, 120*time.Second)
	if !cameBack {
		t.Fatal("the run never came back: the program left a child holding the output " +
			"bridge's write end and the teardown waited on the child it should have killed")
	}
	raw, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatalf("the runner wrote no result (exit code %d): %v", code, err)
	}
	report := string(raw)
	if !strings.HasPrefix(report, "ok: ") {
		t.Fatalf("the runner did not come back clean: %s", report)
	}
	if !strings.Contains(report, "code=7") {
		t.Errorf("the run ended %s, want the program's own exit code 7", report)
	}
	if !strings.Contains(report, "lease=free") {
		t.Errorf("the slot was not free after the run: %s", report)
	}
	_, pidField, found := strings.Cut(report, "pid=")
	if !found {
		t.Fatalf("the runner's report names no child pid: %s", report)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidField))
	if err != nil {
		t.Fatalf("the runner's child pid %q does not parse: %v", pidField, err)
	}
	if !childIsGone(t, pid, 30*time.Second) {
		t.Errorf("the backgrounded child %d outlived the run that left it behind", pid)
	}
}

// insideAPseudoConsole runs commandLine in a fresh child of this test
// binary attached to a Windows pseudo console, waits up to wait for it to
// end, and returns its exit code and whether it came back in time. A child
// that overstays is killed and reported as not having come back: that is
// the shape of the deadlock this test exists to catch, and the timeout is
// what turns it from a hung suite into a failure with a name.
//
// The pty's two directions exist and are kept open but unused: nothing here
// types into the child and nothing drains what it prints to its console.
// The console has to exist and stay attached all the same -- it is what
// makes the child's stdout a console and so what makes the run below build
// the output bridge at all.
func insideAPseudoConsole(t *testing.T, commandLine string, wait time.Duration) (uint32, bool) {
	t.Helper()
	if err := procTeardownCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}

	ptyInRead, ptyInWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ptyInWrite.Close()
	ptyOutRead, ptyOutWrite, err := os.Pipe()
	if err != nil {
		ptyInRead.Close()
		t.Fatal(err)
	}
	defer ptyOutRead.Close()

	var hpc syscall.Handle
	const width, height = 80, 25
	// COORD{X: 80, Y: 25} packed into the single register the x64 calling
	// convention uses for a struct this size, the same packing the proc
	// package's pseudo-console test uses.
	size := uintptr(uint32(uint16(width)) | uint32(uint16(height))<<16)
	r, _, callErr := procTeardownCreatePseudoConsole.Call(size, ptyInRead.Fd(), ptyOutWrite.Fd(), 0, uintptr(unsafe.Pointer(&hpc)))
	// CreatePseudoConsole duplicates what it needs from these; this
	// process's own copies are surplus the moment the call returns.
	ptyInRead.Close()
	ptyOutWrite.Close()
	if r != 0 {
		t.Fatalf("CreatePseudoConsole: hresult 0x%x (%v)", r, callErr)
	}
	defer procTeardownClosePseudoConsole.Call(uintptr(hpc))

	var attrSize uintptr
	procTeardownInitAttrList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrSize)))
	if attrSize == 0 {
		t.Fatal("InitializeProcThreadAttributeList did not report a buffer size")
	}
	attrBuf := make([]byte, attrSize)
	// attrList is a uintptr, invisible to the collector; attrBuf has to stay
	// reachable through every use of attrList below.
	defer runtime.KeepAlive(attrBuf)
	attrList := uintptr(unsafe.Pointer(&attrBuf[0]))
	if r, _, callErr := procTeardownInitAttrList.Call(attrList, 1, 0, uintptr(unsafe.Pointer(&attrSize))); r == 0 {
		t.Fatalf("InitializeProcThreadAttributeList: %v", callErr)
	}
	defer procTeardownDeleteAttrList.Call(attrList)
	if r, _, callErr := procTeardownUpdateAttr.Call(attrList, 0, teardownPseudoConsoleAttribute, uintptr(hpc), unsafe.Sizeof(hpc), 0, 0); r == 0 {
		t.Fatalf("UpdateProcThreadAttribute: %v", callErr)
	}

	var startup teardownStartupInfoEx
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.attributeList = attrList

	var created syscall.ProcessInformation
	line, err := syscall.UTF16PtrFromString(commandLine)
	if err != nil {
		t.Fatal(err)
	}
	// bInheritHandles is deliberately false: with the pseudo-console
	// attribute set, the child's console comes from the attachment, not
	// from inherited handles.
	r, _, callErr = procTeardownCreateProcess.Call(
		0, uintptr(unsafe.Pointer(line)), 0, 0, 0, teardownExtendedStartupInfo, 0, 0,
		uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&created)))
	runtime.KeepAlive(line)
	if r == 0 {
		t.Fatalf("CreateProcessW: %v", callErr)
	}
	defer syscall.CloseHandle(created.Thread)
	defer syscall.CloseHandle(created.Process)

	done := make(chan error, 1)
	go func() {
		_, waitErr := syscall.WaitForSingleObject(created.Process, syscall.INFINITE)
		done <- waitErr
	}()
	select {
	case waitErr := <-done:
		if waitErr != nil {
			t.Fatal(waitErr)
		}
	case <-time.After(wait):
		procTeardownTerminate.Call(uintptr(created.Process), 1)
		return 0, false
	}

	var code uint32
	procTeardownGetExitCode.Call(uintptr(created.Process), uintptr(unsafe.Pointer(&code)))
	return code, true
}

// childIsGone answers whether the process pid is dead, waiting up to wait
// for its object to signal. Termination is not instantaneous -- the job's
// kill is still working in the milliseconds after the run returns -- so the
// wait is the measurement and the bound keeps a genuine survivor from
// hanging the suite. Opening by pid can in principle reach a different
// process if the kernel handed the number out again in between; on the
// seconds this test spans that would take a creation and a recycle the
// choreography has no room for, and the bound turns even that into a report
// instead of a hang.
func childIsGone(t *testing.T, pid int, wait time.Duration) bool {
	t.Helper()
	const synchronize = 0x00100000
	const queryLimitedInformation = 0x1000
	h, _, _ := procTeardownOpenProcess.Call(synchronize|queryLimitedInformation, 0, uintptr(pid))
	if h == 0 {
		return true // nothing to open: the process is already gone
	}
	defer syscall.CloseHandle(syscall.Handle(h))
	r, _, _ := procTeardownWait.Call(h, uintptr(wait.Milliseconds()))
	return r == 0 // WAIT_OBJECT_0: the object signaled, the process is dead
}

// teardownRunner is the console-attached child the test starts: its stdout
// is a real console, so the run it makes builds the output bridge a real
// interactive run builds -- the bridge the whole finding is about. It holds
// the slot the way the command that owns a run holds it, runs the
// backgrounder through the real stub, and reports what came back: the exit
// code, whether the slot came free, and the pid the program left behind,
// which the test checks for death from outside.
func teardownRunner(resultFile, group, groupSID, account, password, stub, dir, pidFile string) int {
	report := func(ok bool, msg string) int {
		prefix := "error: "
		if ok {
			prefix = "ok: "
		}
		_ = os.WriteFile(resultFile, []byte(prefix+msg), 0o600)
		if ok {
			return 0
		}
		return teardownBroke | 1
	}
	// The pseudo console makes this child a real console, but GetStdHandle
	// keeps whatever raw values CreateProcessW happened to copy in -- the
	// gap the proc package's fixupStdinFromConin compensates for on the
	// input side. This is the same fixup, for all three handles, done here
	// because that helper is unexported where it lives: standard handles
	// that are not real handles would fail the run's own
	// duplicateStandardHandles before anything worth measuring could
	// happen.
	if in := consoleDevice("CONIN$"); in != nil {
		os.Stdin = in
	}
	out := consoleDevice("CONOUT$")
	if out == nil {
		return report(false, "CONOUT$ did not open in the pseudo-console child")
	}
	os.Stdout = out
	errOut := consoleDevice("CONOUT$")
	if errOut == nil {
		return report(false, "a second CONOUT$ did not open in the pseudo-console child")
	}
	os.Stderr = errOut
	if !stdoutIsAConsole() {
		return report(false, "the runner's own stdout is not a console, so the run would build "+
			"no output bridge and this test would prove nothing")
	}

	// The program: this same binary, started through the real stub, which
	// leaves a backgrounded child holding its inherited output and ends on
	// a code of its own.
	program := syscall.EscapeArg(stub) + " " + teardownBackgrounderFlag + " " + syscall.EscapeArg(pidFile)
	line, err := exec.StubLine(stub, groupSID, program)
	if err != nil {
		return report(false, "building the stub line: "+err.Error())
	}
	release, err := lock.Lease(group, 5*time.Second)
	if err != nil {
		return report(false, "taking the slot: "+err.Error())
	}
	code, runErr := proc.RunAsAccountWithLease(account, password, line, dir, os.Environ(), lock.SlotPath(group))
	release()
	if runErr != nil {
		return report(false, fmt.Sprintf("the run failed: %v", runErr))
	}
	// The slot, taken again the moment the command layer's release ran:
	// nothing may still hold it. This is the "the lease is free" half of
	// the closing criterion, and it is only worth measuring after the
	// release, because the release is what a returned run owes.
	again, err := lock.Lease(group, 2*time.Second)
	if err != nil {
		return report(false, fmt.Sprintf("the run returned %d but the slot did not come free: %v", code, err))
	}
	again()
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		return report(false, fmt.Sprintf("the run returned %d but the program left no child pid behind: %v", code, err))
	}
	return report(true, fmt.Sprintf("code=%d lease=free pid=%s", code, strings.TrimSpace(string(raw))))
}

// consoleDevice opens one of the console's device names, or says no.
func consoleDevice(name string) *os.File {
	wide, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil
	}
	handle, err := syscall.CreateFile(wide, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(handle), name)
}

// stdoutIsAConsole is the check duplicateOutput itself makes, spelled out
// here because the proc package's copy of it is unexported: if this is not
// true, the run builds no bridge and this test would pass over a hang that
// never existed.
func stdoutIsAConsole() bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(os.Stdout.Fd()), &mode) == nil
}

// teardownBackgrounder is the program of the run: it starts a child of its
// own, hands the child's pid to the test through the one file the two sides
// share, and ends on its own code -- leaving the child behind, which is the
// whole point. The child inherits this process's standard output, which on
// the chain the runner built is a duplicate of the bridge pipe's write end:
// the same inheritance a shell's background job takes of the shell's
// stdout.
func teardownBackgrounder(pidFile string) int {
	exe, err := os.Executable()
	if err != nil {
		return teardownBroke | 2
	}
	child := goexec.Command(exe, teardownSlouchFlag)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return teardownBroke | 3
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		return teardownBroke | 4
	}
	// Deliberately no Wait: leaving the child running is what is being
	// measured. It is in the job -- everything the program starts joins it
	// automatically -- and the job's kill is what is supposed to end it.
	return 7
}

// teardownSlouch is the backgrounded child: it writes nothing, reads
// nothing, and simply keeps holding what it inherited for as long as it
// lives. The life is meant to be ended by the job's kill; if it ever ends
// on its own, the code says so, far from any code a real ending would use.
func teardownSlouch() int {
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	return teardownBroke | 5
}
