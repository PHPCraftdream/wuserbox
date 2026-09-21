// The console host shut (conhost.go) measured from the only seat an attacker
// needs: a restricted token of the account the host itself runs as. The
// three-object shut -- the token's default list, the process's list, every
// thread it already has -- is shield.go's argument applied to somebody
// else's process; what is measured here is that an unshielded host is wide
// open to that token, and that after the shut the same token is left with
// nothing but itself.

package proc

import (
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// aConhostOfOurOwn gives this process a console host of its own, the way a
// run that attaches a program to a console of its own gets one:
// CreatePseudoConsole, whose host is a child of the caller and is found the
// only way production finds one, ConsoleHostChildren's walk by parentage.
// The pid answered is the difference between the walk before and the walk
// after, and exactly one new pid is tolerated -- anything else means the
// walk cannot tell this test's host from a stranger's, and nothing measured
// against a wrong pid would mean anything.
//
// The pty is shaped exactly like probeInsideAPseudoConsole's: two pipe
// pairs, the packed COORD for 80x25, and the test's own copies of the
// input-read and output-write ends closed the moment CreatePseudoConsole
// returns, which duplicates what it needs. Nothing is ever attached to this
// console, so the output drain below expects to sit idle; it exists so a
// host that did write could never block on a full pipe, which would be a
// failure of plumbing and not of whatever was being measured. The drain's
// reader is closed by the cleanup, after the pseudo console itself, so it is
// the host going away that ends it.
func aConhostOfOurOwn(t *testing.T) (syscall.Handle, uint32) {
	t.Helper()
	before, err := ConsoleHostChildren(uint32(syscall.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	ptyInRead, ptyInWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ptyOutRead, ptyOutWrite, err := os.Pipe()
	if err != nil {
		ptyInRead.Close()
		ptyInWrite.Close()
		t.Fatal(err)
	}
	var hpc syscall.Handle
	// COORD{X: 80, Y: 25} packed into the single register the x64 calling
	// convention uses for a struct this size: X in the low 16 bits, Y in the
	// next 16, the way probeInsideAPseudoConsole packs it.
	const width, height = 80, 25
	size := uintptr(uint32(uint16(width)) | uint32(uint16(height))<<16)
	r, _, callErr := procCreatePseudoConsole.Call(size, ptyInRead.Fd(), ptyOutWrite.Fd(), 0,
		uintptr(unsafe.Pointer(&hpc)))
	ptyInRead.Close()
	ptyOutWrite.Close()
	if r != 0 {
		ptyInWrite.Close()
		ptyOutRead.Close()
		t.Fatalf("CreatePseudoConsole: hresult 0x%x (%v)", r, callErr)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := ptyOutRead.Read(buf); err != nil {
				return
			}
		}
	}()
	after, err := ConsoleHostChildren(uint32(syscall.Getpid()))
	if err != nil {
		procClosePseudoConsole.Call(uintptr(hpc))
		ptyInWrite.Close()
		ptyOutRead.Close()
		t.Fatal(err)
	}
	var fresh []uint32
	for _, pid := range after {
		seen := false
		for _, old := range before {
			if old == pid {
				seen = true
				break
			}
		}
		if !seen {
			fresh = append(fresh, pid)
		}
	}
	if len(fresh) != 1 {
		procClosePseudoConsole.Call(uintptr(hpc))
		ptyInWrite.Close()
		ptyOutRead.Close()
		t.Fatalf("creating a pseudo console did not leave exactly one new console host: before %v, after %v",
			before, after)
	}
	pid := fresh[0]
	t.Cleanup(func() {
		// The close is one-time, and the test may already have made it -- the
		// control's host dies between the halves, on purpose. Closing a
		// handle that has gone back to the table hands whatever object the
		// value names by then to ClosePseudoConsole, so the host's presence
		// in this process's own walk -- parentage and name, the same test
		// ConsoleHostChildren exists for -- is what says the close is still
		// ours to make. A walk that errors says nothing either way, and there
		// the ordinary case is a host still to shut.
		ours := true
		if hosts, err := ConsoleHostChildren(uint32(syscall.Getpid())); err == nil {
			ours = false
			for _, host := range hosts {
				if host == pid {
					ours = true
					break
				}
			}
		}
		if ours {
			procClosePseudoConsole.Call(uintptr(hpc))
		}
		ptyInWrite.Close()
		ptyOutRead.Close()
	})
	return hpc, pid
}

// prowlTheHost runs the prowler against pid from the seat every claim here is
// measured from: this account's own token, restricted, the way
// token.AsSandbox narrows a real run's. The exit code is prowl's report, read
// after the prowler has finished, the same way
// TestASecondStubIsNotOpenToAnAlreadyRunningSandbox reads its prowler's.
func prowlTheHost(t *testing.T, pid uint32) int {
	t.Helper()
	restricted, err := token.AsSandbox(nobodysGroup, "")
	if err != nil {
		t.Fatal(err)
	}
	defer restricted.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	line := syscall.EscapeArg(exe) + " " + prowlerFlag + " " + strconv.FormatUint(uint64(pid), 10)
	code, err := Run(restricted, line, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// TestAConsoleHostShutToItsAccountIsClosedToARestrictedToken is the P0-1
// regression, measured without a second account or administrator rights: a
// console host is open to everything a restricted token of its own account
// asks of it, and ShieldConhost leaves that token nothing but the prowler
// itself.
//
// The pair is what gives the regression meaning, and the order is
// load-bearing. The first host is the control, and it runs first: the doors
// have to really be open on this machine, or the shut below would be
// refusing a prowler that was never getting in anyway, and the pass would
// measure nothing. The control is also changed by being probed -- prowl's
// rewriteAndWearItsToken opens the host for WRITE_DAC and rewrites its
// permission list to allow the account everything -- so what comes out of
// half one is no longer a host ShieldConhost would ever be handed. That is
// why it is torn down before the second half, and why the regression builds
// a fresh host: shut, the list is protected, and what the control measured
// open has to be measured shut on the same kind of host it was measured open
// on.
//
// What this does NOT measure: the account crossing, a host shut to its
// account being attacked from another account's sandbox, which is
// internal/e2e's TestEveryConsoleHostOfARunIsClosedToTheSandboxedProgram and
// needs administrator rights -- and the wiring, that takeConsoleRelay
// actually hands each host it takes to ShieldConhost, which is
// internal/sandbox/exec's wiring test to hold. A pass here says the shut
// holds when it is applied; nothing here says it is always applied.
//
// The prowler now asks every thread the walk lists, not the first one the
// snapshot happens to name, and it refuses to report a held shield over an
// unanswerable probe: a door it could not ask sets its own bit, and a run
// carrying that bit fails this test before any refusal is believed.
func TestAConsoleHostShutToItsAccountIsClosedToARestrictedToken(t *testing.T) {
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}

	// Half one, the control: the doors are real on this machine.
	hpc1, pid1 := aConhostOfOurOwn(t)
	code1 := prowlTheHost(t, pid1)
	if code1&middleBroke != 0 {
		t.Fatalf("the prowler broke before it could probe the console host: %d", code1&^middleBroke)
	}
	// The doors the P0-1 mechanism is about -- every one that ends in running
	// code in the host or wearing its token -- measured open.
	const doorsAnUnshieldedHostOpens = reachedAllAccess | reachedDupHandle | reachedVMWrite |
		reachedVMOperation | reachedCreateThread | reachedWriteDac | reachedThread | reachedThreadList |
		reachedQuery | reachedToken
	if code1&doorsAnUnshieldedHostOpens == 0 {
		t.Fatalf("an unshielded console host refused a restricted token everything, so the refusal below would prove nothing")
	}
	t.Logf("the unshielded console host let the restricted token in through: %s", doorsReached(code1))

	// Between the halves: the control's host is closed the way its cleanup
	// closes the second one, and its death is proved, not assumed -- the
	// second half's walk and pid diff are only clean if it is gone.
	procClosePseudoConsole.Call(uintptr(hpc1))
	deadline := time.Now().Add(5 * time.Second)
	for {
		hosts, err := ConsoleHostChildren(uint32(syscall.Getpid()))
		if err != nil {
			t.Fatal(err)
		}
		gone := true
		for _, host := range hosts {
			if host == pid1 {
				gone = false
				break
			}
		}
		if gone {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("console host %d was still listed %v after its pseudo console was closed", pid1, hosts)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Half two, the regression: a fresh host, shut to its own account.
	_, pid2 := aConhostOfOurOwn(t)
	me, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := ShieldConhost(me, pid2); err != nil {
		t.Fatal(err)
	}
	code2 := prowlTheHost(t, pid2)
	if code2&middleBroke != 0 {
		t.Fatalf("the prowler broke before it could probe the console host: %d", code2&^middleBroke)
	}
	// The one door that must survive the shut: the prowler's own process,
	// unshielded and open to itself by name. Without it, the refusals below
	// would be the prowler opening nothing at all, not the host holding.
	if code2&openedItself == 0 {
		t.Fatalf("the prowler could not even open itself, so every refusal it reported means nothing")
	}
	// A thread door the prowler could not ask is not evidence of anything
	// but the probe: an unanswerable door must not pass for a held one.
	if code2&threadProbeBroke != 0 {
		t.Fatalf("the prowler could not answer the console host's thread doors, so the refusals it reported are not evidence the shield holds")
	}
	if leaked := code2 &^ openedItself; leaked != 0 {
		t.Errorf("a console host shut to its own account was still open to a restricted token of that account: %s",
			doorsReached(leaked))
	}
}
