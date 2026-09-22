// The console host shut (conhost.go) measured from a real run's seat. The
// three-object shut -- the token's default list, the process's list, every
// thread it already has -- is shield.go's argument applied to somebody else's
// process; what is measured here is that an unshielded host is wide open to a
// restricted token of the account the host runs as, and that after the shut
// the same token is left with nothing but itself.
//
// The seat is built in account_test.go: a dedicated local account, this
// binary started as it with RunAsAccount, the whole choreography below run
// inside that child. The measurement helpers therefore return errors rather
// than failing a testing.T -- the process they run in has none -- and the two
// tests at the bottom are thin: they build the seat, start the child, and
// read the verdict from its exit code.

package proc

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// aConhostOfOurs gives this process a console host of its own, the way a
// run that attaches a program to a console of its own gets one:
// CreatePseudoConsole, whose host is a child of the caller and is found the
// only way production finds one, ConsoleHostChildren's walk by parentage.
// The pid answered is the difference between the walk before and the walk
// after, and exactly one new pid is tolerated -- anything else means the
// walk cannot tell this process's host from a stranger's, and nothing
// measured against a wrong pid would mean anything.
//
// The pty is shaped exactly like probeInsideAPseudoConsole's: two pipe
// pairs, the packed COORD for 80x25, and this process's own copies of the
// input-read and output-write ends closed the moment CreatePseudoConsole
// returns, which duplicates what it needs. Nothing is ever attached to this
// console, so the output drain below expects to sit idle; it exists so a
// host that did write could never block on a full pipe, which would be a
// failure of plumbing and not of whatever was being measured. The drain's
// reader is closed by closeAConhost, after the pseudo console itself, so it
// is the host going away that ends it.
func aConhostOfOurs() (syscall.Handle, uint32, error) {
	before, err := ConsoleHostChildren(uint32(syscall.Getpid()))
	if err != nil {
		return 0, 0, err
	}
	ptyInRead, ptyInWrite, err := os.Pipe()
	if err != nil {
		return 0, 0, err
	}
	ptyOutRead, ptyOutWrite, err := os.Pipe()
	if err != nil {
		ptyInRead.Close()
		ptyInWrite.Close()
		return 0, 0, err
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
		return 0, 0, fmt.Errorf("CreatePseudoConsole: hresult 0x%x (%w)", r, callErr)
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
		return 0, 0, err
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
		return 0, 0, fmt.Errorf("creating a pseudo console did not leave exactly one new console host: before %v, after %v",
			before, after)
	}
	return hpc, fresh[0], nil
}

// closeAConhost tears down what aConhostOfOurs built: the pseudo console,
// then both pipe ends, the drain included.
//
// The close is one-time, and the caller may already have made it -- the
// control's host dies between the halves, on purpose. Closing a handle that
// has gone back to the table hands whatever object the value names by then
// to ClosePseudoConsole, so the host's presence in this process's own walk
// -- parentage and name, the same test ConsoleHostChildren exists for -- is
// what says the close is still ours to make. A walk that errors says nothing
// either way, and there the ordinary case is a host still to shut.
func closeAConhost(hpc syscall.Handle, pid uint32) {
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
}

// heldHost carries one host's close so measureConhostShut can reach it from
// more than one path -- the explicit close between the halves, and the
// deferred one every error return runs through -- while keeping that close
// one-time: after the first, the pid is forgotten, so no second call can
// reach closeAConhost with a handle value whose host is already gone. A
// double ClosePseudoConsole on a recycled handle value is exactly the
// accident the walk guard inside closeAConhost exists to prevent; this keeps
// the second call from ever being made.
type heldHost struct {
	hpc syscall.Handle
	pid uint32
}

func (h *heldHost) close() {
	if h.pid == 0 {
		return
	}
	closeAConhost(h.hpc, h.pid)
	h.pid = 0
}

// The fixture child is born by RunAsAccount with CREATE_NO_WINDOW, so it has
// a birth console host of its own that shows up in ConsoleHostChildren's
// walk late -- measured about 150 ms after the process it hosts, the lag
// conhost.go documents. The before/after diff aConhostOfOurs takes must not
// mistake that late arrival for the host it just created, so the
// choreography waits for the walk to settle first, polling this often, for
// at most this long -- the same step and ceiling
// internal/sandbox/exec/console.go polls the same lag with.
const (
	hostWalkPollStep = 25 * time.Millisecond
	hostWalkPollWant = 3 * time.Second
)

// waitUntilHostWalkSettles polls ConsoleHostChildren until two walks a step
// apart answer the same list, which is the only observable meaning "the birth
// host has arrived" has here. A walk that keeps changing to the end of the
// ceiling is refused, with the lists it was still seeing, because a diff
// taken against an unsettled walk would measure the wrong host.
func waitUntilHostWalkSettles() error {
	last, err := ConsoleHostChildren(uint32(syscall.Getpid()))
	if err != nil {
		return err
	}
	deadline := time.Now().Add(hostWalkPollWant)
	for {
		time.Sleep(hostWalkPollStep)
		now, err := ConsoleHostChildren(uint32(syscall.Getpid()))
		if err != nil {
			return err
		}
		if samePids(now, last) {
			return nil
		}
		last = now
		if time.Now().After(deadline) {
			return fmt.Errorf("the console host walk never settled within %v: %v then %v",
				hostWalkPollWant, last, now)
		}
	}
}

func samePids(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// prowlHost runs the prowler against pid from the seat every claim here is
// measured from: this process's own account restricted, the way
// token.AsSandbox narrows a real run's -- and this process is the fixture,
// running as the account, so the seat is the account's. AsSandbox puts the
// account's own identifier in the restricting list, which is what makes the
// second access check the two-check rule that decides every door below the
// one a real run's program sits behind. The exit code is prowl's report, read
// after the prowler has finished.
func prowlHost(pid uint32, dir string) (int, error) {
	restricted, err := token.AsSandbox(nobodysGroup, "")
	if err != nil {
		return 0, err
	}
	defer restricted.Close()
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	line := syscall.EscapeArg(exe) + " " + prowlerFlag + " " + strconv.FormatUint(uint64(pid), 10)
	return Run(restricted, line, dir)
}

// measureConhostShut is the regression's whole choreography, in the account's
// seat: half one measures the doors of an unshielded host, the control is
// torn down, and half two builds a fresh host, shuts it to the account it
// runs as, and measures the same doors again. Every old Fatalf is a returned
// error carrying the same words.
func measureConhostShut(dir string) error {
	if err := procCreatePseudoConsole.Find(); err != nil {
		return fmt.Errorf("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+): %w", err)
	}
	if err := waitUntilHostWalkSettles(); err != nil {
		return err
	}

	// Half one, the control: the doors are real on this machine.
	hpc1, pid1, err := aConhostOfOurs()
	if err != nil {
		return err
	}
	control := &heldHost{hpc: hpc1, pid: pid1}
	defer control.close()
	code1, err := prowlHost(pid1, dir)
	if err != nil {
		return err
	}
	if code1&middleBroke != 0 {
		return fmt.Errorf("the prowler broke before it could probe the console host: %d", code1&^middleBroke)
	}
	// The doors the P0-1 mechanism is about -- every one that ends in running
	// code in the host or wearing its token -- measured open.
	const doorsAnUnshieldedHostOpens = reachedAllAccess | reachedDupHandle | reachedVMWrite |
		reachedVMOperation | reachedCreateThread | reachedWriteDac | reachedThread | reachedThreadList |
		reachedQuery | reachedToken
	if code1&doorsAnUnshieldedHostOpens == 0 {
		return fmt.Errorf("an unshielded console host refused a restricted token everything, so the refusal below would prove nothing")
	}
	fmt.Fprintf(os.Stderr, "the unshielded console host let the restricted token in through: %s\n", doorsReached(code1))

	// Between the halves: the control's host is closed the way the deferred
	// close closes the second one, and its death is proved, not assumed --
	// the second half's walk and pid diff are only clean if it is gone.
	control.close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		hosts, err := ConsoleHostChildren(uint32(syscall.Getpid()))
		if err != nil {
			return err
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
			return fmt.Errorf("console host %d was still listed %v after its pseudo console was closed", pid1, hosts)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Half two, the regression: a fresh host, shut to its own account.
	hpc2, pid2, err := aConhostOfOurs()
	if err != nil {
		return err
	}
	regression := &heldHost{hpc: hpc2, pid: pid2}
	defer regression.close()
	me, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	if err := ShieldConhost(me, pid2); err != nil {
		return err
	}
	code2, err := prowlHost(pid2, dir)
	if err != nil {
		return err
	}
	if code2&middleBroke != 0 {
		return fmt.Errorf("the prowler broke before it could probe the console host: %d", code2&^middleBroke)
	}
	// The one door that must survive the shut: the prowler's own process,
	// unshielded and open to itself by name. Without it, the refusals below
	// would be the prowler opening nothing at all, not the host holding.
	if code2&openedItself == 0 {
		return fmt.Errorf("the prowler could not even open itself, so every refusal it reported means nothing")
	}
	// A thread door the prowler could not ask is not evidence of anything
	// but the probe: an unanswerable door must not pass for a held one.
	if code2&threadProbeBroke != 0 {
		return fmt.Errorf("the prowler could not answer the console host's thread doors, so the refusals it reported are not evidence the shield holds")
	}
	if leaked := code2 &^ openedItself; leaked != 0 {
		return fmt.Errorf("a console host shut to its own account was still open to a restricted token of that account: %s",
			doorsReached(leaked))
	}
	return nil
}

// shutFixture is the program this binary becomes when it is started as the
// shut account. The exit code is the verdict and diagnosis.txt is the words
// that explain a failure -- the split the prowler's own exit code works on,
// because the file is the one thing a refusal elsewhere cannot take away.
func shutFixture(dir string) int {
	if err := measureConhostShut(dir); err != nil {
		return fixtureFailed(dir, err)
	}
	return 0
}

// TestAConsoleHostShutToItsAccountIsClosedToARestrictedToken is the P0-1
// regression: a console host is open to everything a restricted token of its
// own account asks of it, and ShieldConhost leaves that token nothing but the
// prowler itself.
//
// It is measured from a real dedicated account's seat, because the old seat
// -- this process's own identity, "without a second account or administrator
// rights" -- stopped being a valid stand-in the day the machine running the
// tests was itself an administrator. The CI runner runs as the built-in
// Administrator (SID ending -500), and ShieldConhost's list refuses that same
// SID first, so every door the old seat asked was answered by the refusal
// aimed at it rather than by the shut under test. A run's real seat is a
// dedicated sandbox account (internal/account), never an administrator, and
// that is the seat this measures from: the account is created, this binary is
// started as it with RunAsAccount -- the launch a real run makes -- and the
// choreography above runs inside it.
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
// The prowler asks every thread the walk lists, not the first one the
// snapshot happens to name, and it refuses to report a held shield over an
// unanswerable probe: a door it could not ask sets its own bit, and a run
// carrying that bit fails before any refusal is believed.
func TestAConsoleHostShutToItsAccountIsClosedToARestrictedToken(t *testing.T) {
	requireAdministrator(t)
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	a := aShutAccount(t, "shld0dea0001", false)
	_, work, exe := fixtureTree(t, a)
	a.runFixture(t, exe, work, shutFixtureFlag)
}

// TestAdministratorsMembershipDoesNotUndoTheShut pins the ordering the shut's
// list is built in. The list keeps the administrators an allow entry so the
// machine can still end a runaway sandbox, and that entry sits AFTER the
// refusal on purpose -- Windows answers with the first entry that matches and
// covers the rights asked, so the refusal reaches the account even when the
// account is a member of that group. That ordering is the property: the
// account is made a member of Administrators before its first logon, the
// identical choreography runs in its seat, and the doors must come back
// closed exactly as they do for an ordinary account. This is also the shape
// the broken tests measured by accident -- a seat that belongs to an
// administrator -- and it is now a deliberate, passing measurement instead of
// a machine-specific failure.
func TestAdministratorsMembershipDoesNotUndoTheShut(t *testing.T) {
	requireAdministrator(t)
	if err := procCreatePseudoConsole.Find(); err != nil {
		t.Skip("CreatePseudoConsole is not available on this Windows build (ConPTY needs Windows 10 1809+)")
	}
	a := aShutAccount(t, "shld0dea0002", true)
	_, work, exe := fixtureTree(t, a)
	a.runFixture(t, exe, work, shutFixtureFlag)
}
