// The born-shut half of the shield, measured directly. The ACCESS_DENIED
// branch of shutThreadsAlreadyRunningOnce counts a thread shut on the
// strength of one refused WRITE_DAC -- a refusal it cannot verify by reading
// the list back, because READ_CONTROL is refused too once a thread is shut.
// What that branch believes, this file builds: threads are created at the
// exact moments the branch reasons about, in a process this test owns, and
// afterwards BOTH doors the escape needs -- THREAD_SET_CONTEXT with
// THREAD_SUSPEND_RESUME, the instruction-redirection vector, and WRITE_DAC
// -- are asked from a restricted seat.
//
// The seat is built in account_test.go, and it is what makes the measurement
// the real shape: the process that shields itself is the fixture's dedicated
// account -- the exact identity a run's stub has -- and the prober's
// restricted seat is taken from inside that account's process, exactly the
// relationship stub and program have, so the measurement no longer depends
// on who runs the tests. The stand-in this replaces, the test process's own
// identity, was valid only while that process was never an administrator:
// the CI runner runs as the built-in Administrator (SID ending -500), and
// there the seat's own question was answered by the shut's own refusal aimed
// at the seat's identity -- the control half failed there, deterministically,
// and never locally, which is how a pass everywhere else and a red CI were
// both true at once.
//
// A console host cannot be made to spawn a thread at a chosen moment from
// outside -- injecting one would need the very doors the shield closes -- so
// a stand-in process still stands in for the stub, the way race_test.go
// stands in for it; the real host's every thread is measured by
// TestAConsoleHostShutToItsAccountIsClosedToARestrictedToken, whose prowler
// asks all of them.

package proc

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

const (
	threadShieldFixtureFlag = "-wuserbox-thread-shield-fixture"
	threadProberFlag        = "-wuserbox-thread-prober"

	// The object kind SetNamedSecurityInfo is pointed at below: the answer
	// file is a file, where everything else in this package's shut work aims
	// at seKernelObject.
	seFileObject = 1
)

var (
	spawnerCreateThread = w32.Kernel32.NewProc("CreateThread")
	spawnerCreateEvent  = w32.Kernel32.NewProc("CreateEventW")
	// Releasing the held threads is a SetEvent on the event they wait on,
	// which is what lets the fixture child end on its own instead of being
	// killed for holding them.
	procSetEvent = w32.Kernel32.NewProc("SetEvent")
	// Named, not through a handle, because the handle os.Create hands back
	// does not carry WRITE_DAC and the call wants the rights on the object
	// checked against itself; naming it lets Windows open the file for
	// exactly that, which the owner may always do.
	procSetNamedSecurityInfo = w32.Advapi32.NewProc("SetNamedSecurityInfoW")
)

// spawnerHoldEvent is the thing every thread the spawner creates waits on.
// It is set by the spawner before it creates any thread, so a thread's body
// never reads it while it is still being written.
var spawnerHoldEvent uintptr

// spawnerThreadBody is the body of a thread created to be held: a
// syscall.NewCallback closure -- logon.go's relay handler is the precedent --
// because a raw Windows thread has no Go scheduler to sit in a channel or a
// sync wait with, and a syscall-level wait is what it can hold without one.
var spawnerThreadBody = syscall.NewCallback(func(_ uintptr) uintptr {
	_, _ = syscall.WaitForSingleObject(syscall.Handle(spawnerHoldEvent), syscall.INFINITE)
	return 0
})

// spawnHeldThread starts one thread that waits on spawnerHoldEvent and
// reports its id. NULL attributes is the point of the call, not an omission:
// with no list of its own named, the thread is given its creator's token's
// default list, which is exactly the inheritance Shield's step one acts on.
func spawnHeldThread() (uint32, bool) {
	var tid uint32
	h, _, _ := spawnerCreateThread.Call(0, 0, spawnerThreadBody, 0, 0, uintptr(unsafe.Pointer(&tid)))
	if h == 0 {
		return 0, false
	}
	syscall.CloseHandle(syscall.Handle(h))
	return tid, true
}

// threadShieldFixture is the program this binary becomes when it is started
// as the fixture's account. The exit code is the verdict and diagnosis.txt
// is the words that explain a failure -- the split the prowler's own exit
// code works on, because the file is the one thing a refusal elsewhere
// cannot take away.
func threadShieldFixture(dir string) int {
	if err := measureBornShut(dir); err != nil {
		return fixtureFailed(dir, err)
	}
	return 0
}

// measureBornShut is the fixture child's whole choreography, in the account's
// seat, playing the process a run shields: it creates a thread at each
// boundary the ACCESS_DENIED branch reasons about -- one before anything is
// shielded, one between the token's default list and the walk -- the branch's
// exact subject -- and one after the walk, which only the token's default
// list can ever have reached. The three steps of Shield run here in their
// real order, on the process the child itself is, and the prober is started
// from in here under a restricted token of the account the child runs as.
// Every failure is a returned error; fixtureFailed writes it down and turns
// it into the exit code the parent reads.
func measureBornShut(dir string) error {
	me, err := sid.CurrentUser()
	if err != nil {
		return fmt.Errorf("naming its own account: %w", err)
	}
	dacl, free, err := selfLockingDacl(me)
	if err != nil {
		return err
	}
	defer free()
	h, _, callErr := spawnerCreateEvent.Call(0, 0, 0, 0)
	if h == 0 {
		return fmt.Errorf("creating the event its threads hold on: %w", callErr)
	}
	spawnerHoldEvent = h
	// Set the event before the handle is closed, so the held threads wake
	// and end instead of the child being found still holding them: a process
	// left holding its threads holds the job open, the same reason a
	// coordinator here kills a stand-in on cleanup.
	defer func() {
		procSetEvent.Call(spawnerHoldEvent)
		syscall.CloseHandle(syscall.Handle(spawnerHoldEvent))
	}()
	t1, ok := spawnHeldThread()
	if !ok {
		return errors.New("CreateThread failed for the first thread")
	}
	restricted, err := token.AsSandbox(nobodysGroup, "")
	if err != nil {
		return err
	}
	defer restricted.Close()

	// Control: before anything is shielded, the same seat opens both doors of
	// the first thread. Without this, a refusal below would also be what a
	// broken build answers, and would prove nothing.
	beforeAnswers := dir + `\answers-before.marker`
	if err := makeAnswerFile(beforeAnswers); err != nil {
		return err
	}
	code, err := runProber(restricted, dir, beforeAnswers, t1)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("the doors were shut before anything was shielded, so the refusals below would prove nothing: prober exit %d", code)
	}
	before, err := readAnswers(beforeAnswers)
	if err != nil {
		return err
	}
	if len(before) != 2 {
		return fmt.Errorf("the prober answered %d asks about a process with one thread and two doors: %v", len(before), before)
	}
	for _, ask := range before {
		if ask.id != t1 || ask.answer != "open" {
			return fmt.Errorf("the doors were shut before anything was shielded, so the refusals below would prove nothing: thread %d door %s answered %s",
				ask.id, ask.door, ask.answer)
		}
	}

	// Shield's step one: the token first, so a thread born from here on is
	// born carrying the list.
	if err := shutFutureThreads(dacl); err != nil {
		return err
	}
	t15, ok := spawnHeldThread()
	if !ok {
		return errors.New("CreateThread failed for the mid-shield thread")
	}
	// Shield's step two: the process's own list, through the pseudo-handle no
	// list is ever checked against.
	if r, _, _ := procSetSecurityInfo.Call(currentProcess, seKernelObject,
		daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, dacl, 0); r != 0 {
		return fmt.Errorf("shutting this process: error %d", r)
	}
	// Shield's step three: the walk over what already exists. The mid-shield
	// thread is in it, and its WRITE_DAC open is refused -- the very refusal
	// the branch counts as a thread already shut.
	if err := shutThreadsAlreadyRunning(dacl, uint32(syscall.Getpid())); err != nil {
		return err
	}
	t2, ok := spawnHeldThread()
	if !ok {
		return errors.New("CreateThread failed for the born-shielded thread")
	}

	labels := map[uint32]string{
		t1:  "the thread born before anything was shielded",
		t15: "the thread born between the token's default list and the walk",
		t2:  "the thread born after the walk, carrying only the token's default list",
	}

	// Measurement: all three threads, both doors, from the same seat. Exit 0
	// says every ask came back definite; what the answers say is judged
	// below.
	afterAnswers := dir + `\answers-after.marker`
	if err := makeAnswerFile(afterAnswers); err != nil {
		return err
	}
	code, err = runProber(restricted, dir, afterAnswers, t1, t15, t2)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("the prober could not answer the shielded process's thread doors, so what it did answer is not evidence: exit %d", code)
	}
	after, err := readAnswers(afterAnswers)
	if err != nil {
		return err
	}
	asked := map[string]bool{}
	var broke []string
	for _, ask := range after {
		asked[ask.door+" "+strconv.FormatUint(uint64(ask.id), 10)] = true
		switch ask.answer {
		case "denied":
			// The door held. This is the measurement.
		case "open":
			broke = append(broke, fmt.Sprintf("%s (%d) opened %s from the restricted seat after the shield",
				labels[ask.id], ask.id, ask.door))
		default:
			broke = append(broke, fmt.Sprintf("%s (%d) could not be answered on %s: %s -- the thread is held alive on an event, so a vanished thread here is not a race, it is a measurement that failed",
				labels[ask.id], ask.id, ask.door, ask.answer))
		}
	}
	for id, what := range labels {
		for _, door := range []string{"redirect", "writeDac"} {
			if !asked[door+" "+strconv.FormatUint(uint64(id), 10)] {
				return fmt.Errorf("the prober never answered %s on %s (%d), so the shield was measured on less than it must hold for", door, what, id)
			}
		}
	}
	if len(broke) > 0 {
		return errors.New(strings.Join(broke, "; "))
	}
	return nil
}

// runProber starts the thread prober under the restricted seat named, with
// the answer file to write and the thread ids to ask about, and returns its
// exit code -- 0 when every ask came back definite. The error return is a
// start that never happened, which is a different kind of broken than an
// answer.
func runProber(restricted syscall.Token, dir, answers string, ids ...uint32) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	line := syscall.EscapeArg(exe) + " " + threadProberFlag + " " + syscall.EscapeArg(answers)
	for _, id := range ids {
		line += " " + strconv.FormatUint(uint64(id), 10)
	}
	return Run(restricted, line, dir)
}

// threadProber asks both doors of each named thread and writes one line per
// ask to answerFile -- "tid door answer" -- ending on 0 when every ask came
// back definite (open or denied), 1 when any ask answered with something
// else or could not be written down, 2 when it was given nothing it could
// run on. It is started from inside the shielding process under a RESTRICTED
// token, and being a separate process is the whole point: the seat decides
// the answer, and a seat with the Administrators group enabled -- what an
// elevated desktop's own token carries, and what the locking list grants
// everything -- would see every door answer open, a measurement that would
// lie about the shield.
func threadProber(answerFile string, ids []uint32) int {
	if len(ids) == 0 {
		return 2
	}
	file, err := os.Create(answerFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "thread prober: opening its answer file:", err)
		return 1
	}
	defer file.Close()
	doors := []struct {
		name   string
		access uintptr
	}{
		{"redirect", threadSetContext | threadSuspendResume},
		{"writeDac", writeDac},
	}
	definite := true
	for _, id := range ids {
		for _, door := range doors {
			var answer string
			h, _, callErr := procOpenThread.Call(door.access, 0, uintptr(id))
			switch {
			case h != 0:
				answer = "open"
				syscall.CloseHandle(syscall.Handle(h))
			case errors.Is(callErr, syscall.Errno(errInvalidParameter)):
				// The thread ended between being named and being asked.
				answer = "gone"
				definite = false
			case errors.Is(callErr, syscall.ERROR_ACCESS_DENIED):
				// A refusal is an answer: the door held.
				answer = "denied"
			default:
				answer = fmt.Sprintf("errno %d", callErr)
				definite = false
			}
			if _, err := fmt.Fprintf(file, "%d %s %s\n", id, door.name, answer); err != nil {
				fmt.Fprintln(os.Stderr, "thread prober: writing its answer:", err)
				return 1
			}
		}
	}
	if !definite {
		return 1
	}
	return 0
}

// threadAnswer is one line of the prober's answer file, parsed.
type threadAnswer struct {
	id     uint32
	door   string
	answer string
}

// readAnswers reads the answer file back. A line that does not parse is the
// measurement breaking rather than an answer the shield can be judged on,
// so it ends the measurement.
func readAnswers(path string) ([]threadAnswer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var answers []threadAnswer
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("the thread prober wrote an answer the test cannot read: %q", line)
		}
		id, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("the thread prober wrote an answer the test cannot read: %q: %w", line, err)
		}
		answers = append(answers, threadAnswer{id: uint32(id), door: fields[1], answer: fields[2]})
	}
	return answers, nil
}

// makeAnswerFile creates the prober's answer file in the account's own work
// directory and then writes onto it a protected list naming the account
// itself. The naming is the point: a restricted token has to pass the access
// check twice, once with its normal SIDs and once with its restricting ones,
// and naming the account -- which AsSandbox puts in the restricting list as
// well as the normal one -- is what lets the same file answer both, the same
// reason the prowler can open an object whose list names the account.
// Protected, so nothing the directory grants is silently added back.
func makeAnswerFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	f.Close()
	me, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	dacl, free, err := listAllowing(me)
	if err != nil {
		return err
	}
	defer free()
	if r, _, callErr := procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, dacl, 0); r != 0 {
		return fmt.Errorf("giving the prober's restricted seat a write of its own on the answer file: error %d (%w)", r, callErr)
	}
	return nil
}

// TestAThreadBornIntoAShieldedProcessIsBornShut measures the claim the
// ACCESS_DENIED branch of shutThreadsAlreadyRunningOnce stands on: that a
// thread born carrying the locking list is closed to the account that owns
// it, so counting a WRITE_DAC refusal as "already shut" counts a shut thread
// and not a missed one.
//
// The branch's belief cannot be checked where it runs -- READ_CONTROL is
// refused too once a thread is shut, so no walk can read the list back to
// confirm what the refusal meant. The only proof that can exist is built the
// other way round, with threads created at the exact moments the branch
// reasons about, and both doors asked from outside afterwards. Three threads,
// three claims:
//
//   - The first, born before anything was shielded, is asked again after the
//     walk: the walk shut what existed -- and what existed was open to this
//     very prober a moment before, which the control half proves.
//   - The second, born between the token's default list and the walk, is the
//     exact thread the ACCESS_DENIED branch reasons about. Whatever the walk
//     believed on seeing its refusal, the dangerous door -- the one that
//     redirects its instructions -- must answer refused when actually asked.
//     The branch's assumption, verified.
//   - The third, born after the walk, carries only the token's default list:
//     the born-shut property itself, the reason Shield orders the token
//     before the walk.
//
// The prober sits in a separate process under a restricted token because the
// seat decides the answer. On an elevated desktop the test process's own
// token carries the Administrators group enabled, and the locking list grants
// that group everything, so asked from in here every door would answer open
// and the measurement would lie. token.AsSandbox with a group nothing on the
// machine belongs to is the seat every other measurement in this package is
// taken from -- and it is taken from inside the account's process, the way a
// real stub narrows a token for the program it starts.
//
// The control half is what gives the shield half meaning: before anything is
// shielded, the same prober opens every door of the first thread. A mutation
// that left any thread open -- a second thread passed over while the first
// was shut, a born-later thread given nothing, an ACCESS_DENIED refusal
// believed over a thread the list never reached -- turns this red, naming
// the thread and the door.
//
// The parent is thin, the way conhost_test.go's parents are: it builds the
// account seat, starts this binary as the account, and reads the verdict
// from the child's exit code.
func TestAThreadBornIntoAShieldedProcessIsBornShut(t *testing.T) {
	a := aShutAccount(t, "shld0dea0003", false)
	_, work, exe := fixtureTree(t, a)
	a.runFixture(t, exe, work, threadShieldFixtureFlag)
}
