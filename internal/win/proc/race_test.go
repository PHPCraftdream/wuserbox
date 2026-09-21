// The P0 this package's stub exists to close, reproduced directly: the
// window between a stub process coming into being and its own code reaching
// Shield, measured against a process already running as the sandbox account
// under a restricted token -- a second concurrent run of the same sandbox,
// which is exactly what token.AsSandbox's own restricting list cannot tell
// apart from the first.
//
// Modeled the way middle_test.go models the rest of this chain, so it needs
// no administrator rights and no real account: this process's own token
// stands in for the account's ordinary one, and token.AsSandbox with a group
// nothing on the machine belongs to stands in for the restricted one a real
// run would carry. What is being measured is the choreography around
// CreateProcessWithLogonW's return and ResumeThread, not which account
// happens to be running it -- see narrowBeforeResume's own comment in
// logon.go for why a real account would not change the answer.

package proc

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

const raceVictimFlag = "-wuserbox-race-victim"

// raceVictim stands in for the stub as RunAsAccount actually starts it: it
// exists, holding whatever token it was created with, before it has done
// anything to defend itself. It blocks on goFile rather than racing its own
// clock against the test, so the attack below has a guaranteed window to work
// in rather than a probable one -- the same reason nothing else in this
// package's tests sleeps and hopes.
//
// It restricts and shields itself once let go, the way the real stub does,
// so a caller that wants to check the boundary closes afterward can.
func raceVictim(goFile string) int {
	if !waitForFile(goFile, 30*time.Second) {
		return middleBroke | 6
	}
	restricted, err := token.AsSandbox(nobodysGroup, "")
	if err != nil {
		return middleBroke | 7
	}
	defer restricted.Close()
	if err := Shield(); err != nil {
		return middleBroke | 8
	}
	return 0
}

// startRaceStub creates the test's stand-in for a freshly logged-on stub
// exactly the way RunAsAccount creates the real one: suspended, so nothing it
// does before being let go can slip past this function's control, and
// assigned to a job before that. own stands in for the account's ordinary
// token; narrowBeforeResume runs before ResumeThread here for the same reason
// it does in logon.go, and on the same terms -- see that function's comment
// for what it does and does not buy.
func startRaceStub(t *testing.T, own syscall.Token, commandLine, accountSID string) (*job, syscall.Handle, uint32) {
	t.Helper()
	j, err := newJob()
	if err != nil {
		t.Fatal(err)
	}
	var startup syscall.StartupInfo
	var created syscall.ProcessInformation
	startup.Cb = uint32(unsafe.Sizeof(startup))
	line, err := syscall.UTF16FromString(commandLine)
	if err != nil {
		j.Close()
		t.Fatal(err)
	}
	// Born the way a real stub is born: createNoWindow rides along with
	// createSuspended because RunAsAccount births every stub
	// createSuspended|createUnicodeEnvironment|createNoWindow (logon.go). The
	// stand-in used to be started without the flag -- and a console-less
	// caller starting a console-subsystem child without it gets the child a
	// new console, and a new console comes with a window on the screen. The
	// victim here waits on a file and shields itself, so it needs no console
	// of any kind; the flag only takes the window away.
	const flags = createSuspended | createNoWindow
	r, _, callErr := procCreateProcessAsUser.Call(uintptr(own), 0, uintptr(unsafe.Pointer(&line[0])),
		0, 0, 1, flags, 0, 0, uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&created)))
	if r == 0 {
		j.Close()
		t.Fatalf("starting the race stub: %v", callErr)
	}
	t.Cleanup(func() { syscall.CloseHandle(created.Thread) })
	if err := j.assign(created.Process); err != nil {
		procTerminateProcess.Call(uintptr(created.Process), 1)
		syscall.CloseHandle(created.Process)
		j.Close()
		t.Fatalf("assigning the race stub to its job: %v", err)
	}
	if err := narrowBeforeResume(created.Process, accountSID); err != nil {
		procTerminateProcess.Call(uintptr(created.Process), 1)
		syscall.CloseHandle(created.Process)
		j.Close()
		t.Fatalf("narrowing the race stub before resuming it: %v", err)
	}
	procResumeThread.Call(uintptr(created.Thread))
	return j, created.Process, created.ProcessId
}

// TestASecondStubIsNotOpenToAnAlreadyRunningSandbox is the regression for the
// P0 this task exists to close.
//
// The topology is siblings, not parent and child: a program already running
// as the sandbox account, holding a token restricted from it -- what a second
// concurrent run of the same sandbox looks like from outside -- against a
// brand new stub the same account is starting. TestTheProgramCannotTurnOnThe
// ProcessThatConfinedIt above answers a different question, parent and child,
// and answers it after Shield has already run; this one is about before.
//
// The attacking process is real and separate, started the same way stubby's
// own program is: token.AsSandbox builds the restricted token, Run starts
// prowlerFlag under it. Its own exit code is prowl's report, read after it
// has finished, while the victim is still blocked on goFile and has reached
// neither AsSandbox nor Shield -- so whatever prowl found, it found before the
// stub had any chance to defend itself, exactly the window the task names.
func TestASecondStubIsNotOpenToAnAlreadyRunningSandbox(t *testing.T) {
	own := ownToken(t)
	me, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	goFile := dir + `\go.marker`

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	victimLine := syscall.EscapeArg(exe) + " " + raceVictimFlag + " " + syscall.EscapeArg(goFile)
	j, victimProcess, victimPid := startRaceStub(t, own, victimLine, me)
	defer j.Close()
	defer syscall.CloseHandle(victimProcess)

	restricted, err := token.AsSandbox(nobodysGroup, "")
	if err != nil {
		t.Fatal(err)
	}
	defer restricted.Close()
	prowlerLine := syscall.EscapeArg(exe) + " " + prowlerFlag + " " + fmt.Sprint(victimPid)
	// Run blocks until the prowler exits, and goFile has not been written yet
	// -- the victim is still waiting for it -- so whatever the prowler found,
	// it found strictly before the victim called AsSandbox or Shield.
	code, err := Run(restricted, prowlerLine, dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(goFile, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := syscall.WaitForSingleObject(victimProcess, uint32(30*time.Second/time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	victimCode, err := finished(victimProcess)
	if err != nil {
		t.Fatal(err)
	}
	if victimCode&middleBroke != 0 {
		t.Fatalf("the race stub failed on its own terms: %d", victimCode&^middleBroke)
	}

	if code&middleBroke != 0 {
		t.Fatalf("the prowler failed before it could try anything: %d", code&^middleBroke)
	}
	// tokenTheft is the P0 in the task's own words: PROCESS_ALL_ACCESS and
	// PROCESS_DUP_HANDLE, opening and duplicating the token, and the
	// WRITE_DAC route to the same thing -- every door that ends in wearing
	// the stub's unrestricted token. This is what narrowBeforeResume closes,
	// and is the failure this test exists to catch.
	const tokenTheft = reachedAllAccess | reachedDupHandle | reachedQuery |
		reachedToken | woreAnUnrestrictedToken | reachedWriteDac | rewroteItsList
	if leaked := code & tokenTheft; leaked != 0 {
		t.Errorf("a process already running as the sandbox account, under a token restricted from it, "+
			"stole a second stub's unrestricted token before that stub had shielded itself: %s",
			doorsReached(leaked))
	}
	// The thread is a different, known-open door: narrowBeforeResume's own
	// comment explains why closing it broke every real run, and it stays
	// open until the stub reaches Shield, same as before this change. Logged
	// rather than asserted on, so the gap stays visible without this test
	// forever failing on something outside what it was built to fix.
	if residual := code &^ tokenTheft &^ middleBroke; residual != 0 {
		t.Logf("still open before Shield runs, as expected: %s", doorsReached(residual))
	}
}
