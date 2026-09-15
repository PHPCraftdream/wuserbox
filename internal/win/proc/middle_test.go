// The programs this binary can be besides a test, and what holds once one of
// them stands between a run and the program it was asked for.
//
// A run is one process deeper than it used to be. wuserbox starts as the
// sandbox's account, and what it starts is wuserbox again, which narrows its
// own token and starts the program under that -- see
// internal/sandbox/exec/stub.go. So there are two job objects now, one inside
// the other, and two processes waiting on an interrupt instead of one. Both
// properties the single-process chain had are re-measured here through that
// shape: the program's exit code comes back, one interrupt is still left to
// the program, and insisting still ends everything.
//
// The middle is modeled rather than imported. The real one is in a package
// that imports this one, and what it adds on top of Run -- a narrower token
// -- changes what the program may touch, not how a console event or a job
// reaches it.

package proc

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

const (
	sleeperFlag = "-wuserbox-sleeper"
	middleFlag  = "-wuserbox-middle"
	prowlerFlag = "-wuserbox-prowler"
	stubbyFlag  = "-wuserbox-stubby"

	// A group nothing on the machine is a member of. What matters below is
	// the restricting list and the two tokens' relationship, never what the
	// group itself reaches.
	nobodysGroup = "S-1-5-21-1111111111-2222222222-3333333333-717171"
)

// TestMain lets `go test` re-exec this same binary as one of the processes
// these tests need around them: the driver that plays wuserbox, the middle
// that plays the stub, or the program at the end of the chain. Everything
// they run is that process's own program, not a test.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == sleeperFlag {
		sleeper(os.Args[2])
		return
	}
	if len(os.Args) > 2 && os.Args[1] == middleFlag {
		os.Exit(middle(os.Args[2]))
	}
	if len(os.Args) > 2 && os.Args[1] == prowlerFlag {
		os.Exit(prowl(os.Args[2]))
	}
	if len(os.Args) > 1 && os.Args[1] == stubbyFlag {
		os.Exit(stubby())
	}
	if os.Getenv(driverEnv) == "1" {
		runDriver()
		return
	}
	os.Exit(m.Run())
}

// sleeper stands in for a program that handles Ctrl+C itself and carries on:
// an agent stopping the turn it is in, a shell clearing its line. It is what
// makes it possible to tell "the keypress reached the program" apart from
// "the run was ended".
//
// It says so as well as surviving. Staying alive proves only that nothing
// killed it, and through two jobs and two other interrupt handlers the
// question worth answering is whether the keypress arrived at all.
func sleeper(pidFile string) {
	heard := make(chan os.Signal, 4)
	signal.Notify(heard, os.Interrupt)
	go func() {
		<-heard
		_ = os.WriteFile(heardFile(pidFile), []byte("heard"), 0o600)
	}()
	_ = os.WriteFile(pidFile, []byte(fmt.Sprint(os.Getpid())), 0o600)
	time.Sleep(30 * time.Second)
}

// heardFile is where the program at the end of the chain says the interrupt
// reached it.
func heardFile(pidFile string) string { return pidFile + ".heard" }

// middle stands in for the stub: it starts the real program in a job of its
// own, waits for it exactly as a run waits out here, and ends on the
// program's own exit code.
func middle(commandLine string) int {
	var own syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		fmt.Fprintln(os.Stderr, "middle: opening its own token:", err)
		return 90
	}
	defer own.Close()
	here, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "middle:", err)
		return 91
	}
	code, err := Run(own, commandLine, here)
	if err != nil {
		fmt.Fprintln(os.Stderr, "middle: starting the program:", err)
		return 92
	}
	return code
}

// middleLine wraps a command line in the middle, the way exec.StubLine wraps
// one in the stub.
func middleLine(commandLine string) string {
	exe, err := os.Executable()
	if err != nil {
		return commandLine // nothing to wrap it in; the caller measures the plain chain
	}
	return syscall.EscapeArg(exe) + " " + middleFlag + " " + syscall.EscapeArg(commandLine)
}

// The access rights a program under a restricted token must not get to the
// process that restricted it. Any one of them is enough to undo the
// restriction: two of them write into it, and the third reaches the one
// object worth taking -- its unrestricted token, which can be duplicated and
// then worn, for the same user, without any privilege at all.
const (
	processAllAccess        = 0x1FFFFF
	processDupHandle        = 0x0040
	processVMWrite          = 0x0020
	processVMOperation      = 0x0008
	processQueryInformation = 0x0400
	tokenDuplicateAccess    = 0x0002
)

var procOpenProcess = w32.Kernel32.NewProc("OpenProcess")

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
	reachedQuery
	reachedToken
	reachedThread
	reachedBadPid
	// The control, and the one bit that has to be set. Shutting a process to
	// its own account could as easily have shut the program out of *itself*,
	// and a great many programs open their own process by name. A run where
	// that stopped working would be a boundary nobody could use.
	openedItself
)

// The other door into a process, and the reason shutting the process alone
// would not have settled this: a thread is an object of its own with a list
// of its own, and one whose instructions can be redirected runs code inside
// the process that owns it. Shield closes all three; this is what tries them.
const (
	threadSetContext    = 0x0010
	threadSuspendResume = 0x0002
)

// aThreadOf finds one thread belonging to pid, so the prowler has something
// to try the other door on. It borrows Shield's own way of listing them,
// which is the point: the prowler looks for exactly what Shield claims to
// have shut.
func aThreadOf(pid int) (uint32, bool) {
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(snapshotOfThreads, 0)
	if snapshot == 0 || snapshot == invalidHandle {
		return 0, false
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	entry := make([]byte, sizeOfThreadEntry32)
	*(*uint32)(unsafe.Pointer(&entry[0])) = sizeOfThreadEntry32
	for step := procThread32First; ; step = procThread32Next {
		if r, _, _ := step.Call(snapshot, uintptr(unsafe.Pointer(&entry[0]))); r == 0 {
			return 0, false
		}
		if *(*uint32)(unsafe.Pointer(&entry[offsetOfOwnerProcess])) == uint32(pid) {
			return *(*uint32)(unsafe.Pointer(&entry[offsetOfThreadID])), true
		}
	}
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
	for _, door := range []struct {
		bit    int
		access uintptr
	}{
		{reachedAllAccess, processAllAccess},
		{reachedDupHandle, processDupHandle},
		{reachedVMWrite, processVMWrite | processVMOperation},
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
	// And the other door: one of its threads, which is a separate object with
	// a list of its own and is not shut by shutting the process.
	if tid, found := aThreadOf(pid); found {
		if h, _, _ := procOpenThread.Call(threadSetContext|threadSuspendResume, 0, uintptr(tid)); h != 0 {
			reached |= reachedThread
			syscall.CloseHandle(syscall.Handle(h))
		}
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
		return 93
	}
	defer restricted.Close()
	if err := Shield(); err != nil {
		fmt.Fprintln(os.Stderr, "stubby: shutting itself to its own account:", err)
		return 94
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "stubby:", err)
		return 95
	}
	here, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "stubby:", err)
		return 96
	}
	line := strings.Join([]string{
		syscall.EscapeArg(exe), prowlerFlag, syscall.EscapeArg(fmt.Sprint(os.Getpid())),
	}, " ")
	code, err := Run(restricted, line, here)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stubby: starting the program:", err)
		return 97
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
		{reachedThread, "redirecting one of its threads"},
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

// middleDriver starts the driver with the middle in the chain. The mode still
// says what the program at the end does and how the driver waits for it; this
// says only that there is one more process in between.
func middleDriver(t *testing.T, mode, dir, resultFile string) *exec.Cmd {
	t.Helper()
	cmd := driverCommand(t, mode, dir, resultFile)
	cmd.Env = append(cmd.Env, driverMiddle+"=1")
	return cmd
}

// TestTheProgramsExitCodeComesBackThroughTheMiddle is the property a run
// cannot do without: `wuserbox go test` has to fail when the tests fail, and
// with the stub in the chain the code is read twice and handed on twice
// before anything sees it.
//
// 7 rather than 1, because 1 is what half the things that go wrong in between
// report on their own.
func TestTheProgramsExitCodeComesBackThroughTheMiddle(t *testing.T) {
	var own syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()

	code, err := Run(own, middleLine(`C:\Windows\System32\cmd.exe /c exit 7`), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Errorf("the run ended with %d, and the program it ran ended with 7", code)
	}
}

// TestTheProgramCannotTurnOnTheProcessThatConfinedIt is the question the
// two-process chain raises and nothing else here answers.
//
// The stub and the program it starts are the same account. The stub holds
// that account's ordinary token; the program holds the restricted one. If the
// program can reach the stub's process object it can take the stub's token,
// wear it -- impersonating a token of one's own user needs no privilege -- and
// the second access check is gone. The file boundary would then be a
// formality, undone from inside without touching a single file permission.
//
// Measured on the shape rather than on a real account, because the shape is
// the whole of it: one process holding an unrestricted token, a second
// holding a token restricted from it, both the same user, and that user's own
// identifier among the restricting ones -- which is exactly what
// token.AsSandbox arranges and what makes an MSYS program start at all.
//
// The stand-in in the middle is what does the restricting, so nothing here
// touches the test binary's own token or its own permissions. That matters:
// restricting this process's token and naming this process's own user is the
// move token.AsSandbox's comment calls catastrophic in the other direction,
// and it is right.
func TestTheProgramCannotTurnOnTheProcessThatConfinedIt(t *testing.T) {
	var own syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	code, err := Run(own, syscall.EscapeArg(exe)+" "+stubbyFlag, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if code >= 93 && code <= 97 {
		t.Fatalf("the stand-in for the stub failed before it could be turned on: exit %d", code)
	}
	if code&openedItself == 0 {
		t.Fatal("the program could not open its own process, so the shutting went too far " +
			"and what follows would pass for the wrong reason")
	}
	if reached := code &^ openedItself; reached != 0 {
		t.Errorf("a program under the restricted token reached the process that restricted it: %s",
			doorsReached(reached))
	}
}

// TestOneInterruptStillReachesTheProgramThroughTheMiddle is the decision that
// a single Ctrl+C belongs to the program, held with two more things in its
// way: the middle's own console control handler, and the middle's own job.
//
// Neither is allowed to swallow it. Almost everything that runs in a sandbox
// treats the first one as its own business -- an agent stops the turn it is
// in, a shell clears its line -- and a run that ended there would kill the
// agent where the person meant to interrupt it.
func TestOneInterruptStillReachesTheProgramThroughTheMiddle(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "result.txt")
	pidFile := filepath.Join(dir, "grandchild.pid")

	procFreeConsole.Call()
	if r, _, callErr := procAllocConsole.Call(); r == 0 {
		t.Fatalf("AllocConsole: %v", callErr)
	}

	cmd := middleDriver(t, "patient", dir, resultFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitForFile(filepath.Join(dir, "ready.marker"), 90*time.Second) {
		t.Fatal("the driver never became ready")
	}
	pid := readPid(t, pidFile)

	if r, _, callErr := procGenerateCtrlEvent.Call(ctrlBreakEvent, uintptr(cmd.Process.Pid)); r == 0 {
		t.Fatalf("GenerateConsoleCtrlEvent: %v", callErr)
	}

	// Ten and not more: the program at the end sleeps for thirty seconds and
	// then ends on its own, which would look exactly like the run being
	// ended. Delivering a console event takes milliseconds, so a wait long
	// enough to eat that margin would only ever turn one failure into
	// another.
	if !waitForFile(heardFile(pidFile), 10*time.Second) {
		t.Error("the interrupt never reached the program at the end of the chain")
	}
	// Long enough that an ending would have happened by now.
	time.Sleep(1500 * time.Millisecond)

	if _, err := os.Stat(resultFile); err == nil {
		t.Errorf("one interrupt ended the run: %s", readReport(t, resultFile))
	}
	if processGone(t, pid, 200*time.Millisecond) {
		t.Error("one interrupt killed a program that was handling it itself")
	}
}

// TestInsistingStillEndsTheRunThroughTheMiddle is the other half: a second
// interrupt, arriving while the first is still recent, ends everything --
// through a program that would otherwise sleep out its thirty seconds, and
// through a job inside a job.
func TestInsistingStillEndsTheRunThroughTheMiddle(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "result.txt")
	pidFile := filepath.Join(dir, "grandchild.pid")

	procFreeConsole.Call()
	if r, _, callErr := procAllocConsole.Call(); r == 0 {
		t.Fatalf("AllocConsole: %v", callErr)
	}

	cmd := middleDriver(t, "patient", dir, resultFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitForFile(filepath.Join(dir, "ready.marker"), 90*time.Second) {
		t.Fatal("the driver never became ready")
	}
	pid := readPid(t, pidFile)

	// Kept up until the run ends rather than pressed exactly twice: Windows
	// delivers each console control event on a thread it creates in the
	// target, so under load two sent back to back can arrive more than two
	// seconds apart, and the second then counts as a new first. Somebody
	// insisting presses again; so does this.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(300 * time.Millisecond):
				procGenerateCtrlEvent.Call(ctrlBreakEvent, uintptr(cmd.Process.Pid))
			}
		}
	}()
	waitDriver(t, cmd, 90*time.Second)
	close(stop)

	report := readReport(t, resultFile)
	if want := fmt.Sprintf("ended code=%d", uint32(statusControlCExit)); !strings.HasPrefix(report, want) {
		t.Errorf("the driver reported %q, and the run should have ended saying it was stopped", report)
	}
	if !processGone(t, pid, 5*time.Second) {
		t.Errorf("the program (pid %d) is still running after the run was ended", pid)
	}
}
