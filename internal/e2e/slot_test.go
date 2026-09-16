// The escape a concurrent run gets at a newborn stub, measured on the
// mechanism a real run uses: two births of the same real local account, the
// first one's program already standing there when the second one's stub is
// born.
//
// The account tests in account_test.go are the fixture this stands on; what
// is new here is the choreography, which is race_test.go's carried over a
// logon. The prowler reports through its exit code and never through a file,
// because a file is a channel the thing under test can be refused and a
// measurement that comes back empty is then indistinguishable from one that
// never happened. The one file in play is the victim's own announcement --
// its pid and a thread of its own, written before it has defended itself --
// which is an input to the test and not a finding of it, the same trade
// middle_test.go makes with its pid file.
//
// It needs administrator rights and skips without them, like every test that
// builds a real account. This puts internal/e2e at nine entries where the
// layout rules ask for about seven. Named rather than quietly picked, as
// CONTRIBUTING asks: it shares the account fixture and nothing else, and
// folding it into a file about file permissions would bury the one test that
// is about a window between processes.

package e2e

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/exec"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

const (
	slotVictimFlag  = "-wuserbox-slot-victim"
	slotProwlerFlag = "-wuserbox-slot-prowler"

	// Kept far from the door bits, for the reason middle_test.go keeps
	// middleBroke there: small sums of the doors below are reachable exit
	// codes, and a stand-in that failed on its own would then read as a
	// program that got in.
	slotVictimBroke = 1 << 20
	slotProwlBroke  = 1 << 21
)

// What the prowler found, one bit each, ended on as its exit code.
const (
	// sawTheVictim is the control: the second stub was born, announced
	// itself, and had not yet defended itself -- the window existed to be
	// measured. Without it, "no doors opened" and "the prowler never found
	// anything" would be indistinguishable answers.
	sawTheVictim = 1 << iota
	// reachedSetContext is the door narrowBeforeResume cannot shut and the
	// one the escape goes through: a thread whose instructions can be
	// redirected runs code inside the newborn stub, where the unrestricted
	// token is the process's own and nothing has to be worn.
	reachedSetContext
	reachedThreadDac
	reachedProcessWrite
	// foundNothing is what the prowler reports when no second stub ever
	// announced itself -- after the lease, the ordinary answer.
	foundNothing
)

// The access rights the escape needs, spelled out rather than asked for as a
// set: a refusal of a set is not a refusal of its members, and the first
// version of the prowler in middle_test.go mistook exactly that for a closed
// door.
const (
	slotProcessVMWrite      = 0x0020
	slotProcessCreateThread = 0x0002
	slotThreadSetContext    = 0x0010
	slotThreadSuspendResume = 0x0002
	slotWriteDac            = 0x40000
)

var (
	procSlotOpenProcess  = w32.Kernel32.NewProc("OpenProcess")
	procSlotOpenThread   = w32.Kernel32.NewProc("OpenThread")
	procSlotThisThreadId = w32.Kernel32.NewProc("GetCurrentThreadId")
)

// slotVictim is the newborn stub as CreateProcessWithLogonW delivers it: born
// as the account, holding the account's unrestricted token, and having done
// nothing to defend itself. It announces a pid and one of its own threads and
// then blocks -- on the go file, not against anybody's clock -- so the window
// stays open for exactly as long as the test wants it, the same trick
// raceVictim in race_test.go uses. RunAsAccount narrows the stub's process
// object before resuming it, as it does today, so what stays open here is
// what stays open on a real newborn stub: the thread.
func slotVictim(pidFile, goFile string) int {
	tid, _, _ := procSlotThisThreadId.Call()
	announcement := fmt.Sprintf("%d %d", os.Getpid(), tid)
	if err := os.WriteFile(pidFile, []byte(announcement), 0o600); err != nil {
		return slotVictimBroke | 1
	}
	if !waitForSlotFile(goFile, 30*time.Second) {
		return slotVictimBroke | 2
	}
	return 0
}

// slotProwl is the program of the first run, running as the sandbox under the
// restricted token every run's program carries: exactly the attacker a
// concurrent run is. It says it is in place, waits for a second stub to
// announce itself, tries the doors the escape needs -- writing the newborn's
// memory and creating threads in it, redirecting one of its threads, and the
// owner's standing route to the same thread -- and ends on what opened.
func slotProwl(readyFile, pidFile string) int {
	// In place before anything else, so the test outside knows the attacker
	// is standing there before it births the stub it attacks. A stub born
	// first and attacked second is a different, weaker measurement: the
	// attack is a program that was already running when the stub was born.
	if err := os.WriteFile(readyFile, []byte("prowling"), 0o600); err != nil {
		return slotProwlBroke | 1
	}
	if !waitForSlotFile(pidFile, 10*time.Second) {
		return foundNothing
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return slotProwlBroke | 2
	}
	var pid, tid uint64
	if _, err := fmt.Sscanf(string(data), "%d %d", &pid, &tid); err != nil {
		return slotProwlBroke | 3
	}
	reached := sawTheVictim
	if h, _, _ := procSlotOpenProcess.Call(slotProcessVMWrite|slotProcessCreateThread, 0, uintptr(pid)); h != 0 {
		reached |= reachedProcessWrite
		syscall.CloseHandle(syscall.Handle(h))
	}
	for _, door := range []struct {
		bit    int
		access uintptr
	}{
		{reachedSetContext, slotThreadSetContext | slotThreadSuspendResume},
		{reachedThreadDac, slotWriteDac},
	} {
		if h, _, _ := procSlotOpenThread.Call(door.access, 0, uintptr(tid)); h != 0 {
			reached |= door.bit
			syscall.CloseHandle(syscall.Handle(h))
		}
	}
	return reached
}

// waitForSlotFile polls for a file to appear, because a file is the one post
// box these processes share: the stub is born by a logon this process cannot
// see into, and its announcement is the single fact the choreography rests
// on. The deadline bounds the wait; nothing here hopes on a sleep.
func waitForSlotFile(path string, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// slotRun is what one birth came back with.
type slotRun struct {
	code int
	err  error
}

// TestASecondStubIsNotBornWhileAProgramOfTheSandboxRuns is the regression for
// the escape the lease exists to close, on the fixture the account tests
// built: a real local account, a program of that account already running --
// the first run of a sandbox -- and a second stub of the same sandbox being
// born while it stands there.
//
// Without the lease, the second birth succeeds and the prowler -- the first
// run's own program -- reaches the newborn through the doors
// narrowBeforeResume leaves open: the thread, which Shield can only shut once
// the stub's own code reaches it. With the lease, the second birth is refused
// before CreateProcessWithLogonW is ever called, and this test passes because
// there was never a stub to attack, not because any door was measured shut.
func TestASecondStubIsNotBornWhileAProgramOfTheSandboxRuns(t *testing.T) {
	requireAdministrator(t)
	root, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, root)
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	box := newRealBox(t, firstSandbox, work)
	box.hand(t, work, grant.RW)
	// The stub, the prowler and the victim are all this test binary standing
	// in for wuserbox.exe, copied where the account can start it -- see
	// stubBinary. Both births start it as the account: the first through the
	// real stub chain, so the prowler is a program the way a run's program
	// is -- restricted, as the account, behind a shielded stub -- and the
	// second directly, which is what a newborn stub is: a process
	// CreateProcessWithLogonW has just made and nothing has defended yet.
	stub := stubBinary(t, root)

	pidFile := filepath.Join(work, "second-stub.pid")
	goFile := filepath.Join(work, "go.marker")
	readyFile := filepath.Join(work, "prowler.ready")

	prowlerLine := syscall.EscapeArg(stub) + " " + slotProwlerFlag + " " +
		syscall.EscapeArg(readyFile) + " " + syscall.EscapeArg(pidFile)
	firstLine, err := exec.StubLine(stub, box.sid, prowlerLine)
	if err != nil {
		t.Fatal(err)
	}
	holder := make(chan slotRun, 1)
	go func() {
		code, err := proc.RunAsAccount(box.account, box.password, firstLine, work, os.Environ(), box.group)
		holder <- slotRun{code, err}
	}()

	// The stub must be born under an attacker that is already standing
	// there, and not merely started first. That the prowler is running also
	// means the first run is past its own lease, so the second birth below
	// meets a held slot rather than a race between two takes.
	waitAttackerReady(t, holder, readyFile)

	victim := make(chan slotRun, 1)
	victimLine := syscall.EscapeArg(stub) + " " + slotVictimFlag + " " +
		syscall.EscapeArg(pidFile) + " " + syscall.EscapeArg(goFile)
	go func() {
		code, err := proc.RunAsAccount(box.account, box.password, victimLine, work, os.Environ(), box.group)
		victim <- slotRun{code, err}
	}()

	// The prowler ends when it has finished trying every door, so its run
	// ending -- and not any guess about timing -- is what says the window is
	// over. Only then is the victim let go.
	var attacker slotRun
	select {
	case attacker = <-holder:
	case <-time.After(90 * time.Second):
		t.Fatal("the first run never ended")
	}
	if attacker.err != nil {
		t.Fatalf("the first run failed: %v", attacker.err)
	}
	if err := os.WriteFile(goFile, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	var second slotRun
	select {
	case second = <-victim:
	case <-time.After(60 * time.Second):
		t.Fatal("the second run never ended")
	}

	// The lease's answer, and the shape of the pass: the second run was
	// refused, there was no second stub, so there was no window and nothing
	// for a standing program of the account to reach. Asserting the refusal
	// here rather than a closed door is the point of the test.
	if errors.Is(second.err, lock.ErrSlotHeld) {
		if attacker.code&^foundNothing != 0 {
			t.Errorf("the second stub was never born, yet the prowler reports: %s", slotDoors(attacker.code))
		}
		return
	}
	if second.err != nil {
		t.Fatalf("the second run neither ran nor was refused by the lease: %v", second.err)
	}
	if second.code != 0 {
		t.Fatalf("the second stub's stand-in ended with %d, on its own terms", second.code&^slotVictimBroke)
	}
	if attacker.code&sawTheVictim == 0 {
		t.Fatalf("the prowler never found the second stub it was born to attack, so this run measured nothing: %s",
			slotDoors(attacker.code))
	}
	if doors := attacker.code & (reachedSetContext | reachedThreadDac | reachedProcessWrite); doors != 0 {
		t.Errorf("a program already running as the sandbox account, under a token restricted from it, "+
			"reached the second stub of the same sandbox while that stub was being born: %s",
			slotDoors(doors))
	}
}

// waitAttackerReady blocks until the first run's program says it is in place,
// or says the first run failed while getting there -- a refusal, a logon
// failure, anything. Peeking the channel on every pass is what tells those
// apart: a first run that never started would otherwise cost the whole wait
// before it said so.
func waitAttackerReady(t *testing.T, holder <-chan slotRun, readyFile string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		select {
		case r := <-holder:
			t.Fatalf("the first run failed before its program was in place: %v", r.err)
		default:
		}
		if _, err := os.Stat(readyFile); err == nil {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatal("the first run's program never reported itself running")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// slotDoors spells out a prowler's exit code, the way doorsReached spells out
// a prowl's in middle_test.go.
func slotDoors(code int) string {
	named := []struct {
		bit  int
		what string
	}{
		{sawTheVictim, "it found the second stub"},
		{reachedSetContext, "redirecting one of its threads (THREAD_SET_CONTEXT)"},
		{reachedThreadDac, "rewriting one of its threads' permission lists (WRITE_DAC)"},
		{reachedProcessWrite, "writing its memory and creating threads in it (PROCESS_VM_WRITE, PROCESS_CREATE_THREAD)"},
		{foundNothing, "nothing: no second stub ever existed"},
		{slotProwlBroke, "(the prowler broke before it could try anything)"},
		{slotVictimBroke, "(the victim broke)"},
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
