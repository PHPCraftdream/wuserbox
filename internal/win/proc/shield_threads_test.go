// The born-shut half of the shield, measured directly. The ACCESS_DENIED
// branch of shutThreadsAlreadyRunningOnce counts a thread shut on the
// strength of one refused WRITE_DAC -- a refusal it cannot verify by reading
// the list back, because READ_CONTROL is refused too once a thread is shut.
// What that branch believes, this file builds: threads are created at the
// exact moments the branch reasons about, in a process this test owns, and
// afterwards BOTH doors the escape needs -- THREAD_SET_CONTEXT with
// THREAD_SUSPEND_RESUME, the instruction-redirection vector, and WRITE_DAC
// -- are asked from the restricted seat every other measurement in this
// package uses.
//
// A console host cannot be made to spawn a thread at a chosen moment from
// outside -- injecting one would need the very doors the shield closes -- so
// the mechanism is measured on a stand-in process, the way race_test.go
// stands in for the stub; the real host's every thread is measured by
// TestAConsoleHostShutToItsAccountIsClosedToARestrictedToken, whose prowler
// now asks all of them. Needs no administrator rights.

package proc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

const (
	threadSpawnerFlag = "-wuserbox-thread-spawner"
	threadProberFlag  = "-wuserbox-thread-prober"

	// The object kind SetNamedSecurityInfo is pointed at below: the answer
	// file is a file, where everything else in this package's shut work aims
	// at seKernelObject.
	seFileObject = 1
)

var (
	spawnerCreateThread = w32.Kernel32.NewProc("CreateThread")
	spawnerCreateEvent  = w32.Kernel32.NewProc("CreateEventW")
	// Named, not through a handle, because the handle the coordinator holds
	// from creating the file does not carry WRITE_DAC and the call wants the
	// rights on the object checked against itself; naming it lets Windows
	// open the file for exactly that, which the owner may always do.
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

// threadSpawner plays the process a run shields, with a thread created at
// each boundary the ACCESS_DENIED branch reasons about: one before anything
// is shielded, one between the token's default list and the walk -- the
// branch's exact subject -- and one after the walk, which only the token's
// default list can ever have reached. The three steps of Shield run here in
// their real order, on the process the spawner itself is. Every failure
// ends middleBroke|N with a line on stderr, the way the stand-ins here
// report breaking on their own terms.
func threadSpawner(dir string) int {
	me, err := sid.CurrentUser()
	if err != nil {
		fmt.Fprintln(os.Stderr, "thread spawner: naming its own account:", err)
		return middleBroke | 1
	}
	dacl, free, err := selfLockingDacl(me)
	if err != nil {
		fmt.Fprintln(os.Stderr, "thread spawner:", err)
		return middleBroke | 2
	}
	defer free()
	h, _, callErr := spawnerCreateEvent.Call(0, 0, 0, 0)
	if h == 0 {
		fmt.Fprintln(os.Stderr, "thread spawner: creating the event its threads hold on:", callErr)
		return middleBroke | 3
	}
	spawnerHoldEvent = h
	t1, ok := spawnHeldThread()
	if !ok {
		fmt.Fprintln(os.Stderr, "thread spawner: CreateThread failed for the first thread")
		return middleBroke | 4
	}
	if err := os.WriteFile(dir+`\t1.marker`, []byte(strconv.FormatUint(uint64(t1), 10)), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "thread spawner:", err)
		return middleBroke | 5
	}
	if !waitForFile(dir+`\go.marker`, 30*time.Second) {
		fmt.Fprintln(os.Stderr, "thread spawner: the coordinator never wrote go.marker")
		return middleBroke | 6
	}
	// Shield's step one: the token first, so a thread born from here on is
	// born carrying the list.
	if err := shutFutureThreads(dacl); err != nil {
		fmt.Fprintln(os.Stderr, "thread spawner:", err)
		return middleBroke | 7
	}
	t15, ok := spawnHeldThread()
	if !ok {
		fmt.Fprintln(os.Stderr, "thread spawner: CreateThread failed for the mid-shield thread")
		return middleBroke | 8
	}
	// Shield's step two: the process's own list, through the pseudo-handle no
	// list is ever checked against.
	if r, _, _ := procSetSecurityInfo.Call(currentProcess, seKernelObject,
		daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, dacl, 0); r != 0 {
		fmt.Fprintf(os.Stderr, "thread spawner: shutting this process: error %d\n", r)
		return middleBroke | 9
	}
	// Shield's step three: the walk over what already exists. The mid-shield
	// thread is in it, and its WRITE_DAC open is refused -- the very refusal
	// the branch counts as a thread already shut.
	if err := shutThreadsAlreadyRunning(dacl, uint32(syscall.Getpid())); err != nil {
		fmt.Fprintln(os.Stderr, "thread spawner:", err)
		return middleBroke | 10
	}
	t2, ok := spawnHeldThread()
	if !ok {
		fmt.Fprintln(os.Stderr, "thread spawner: CreateThread failed for the born-shielded thread")
		return middleBroke | 11
	}
	ready := strconv.FormatUint(uint64(t15), 10) + " " + strconv.FormatUint(uint64(t2), 10)
	if err := os.WriteFile(dir+`\ready.marker`, []byte(ready), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "thread spawner:", err)
		return middleBroke | 12
	}
	if !waitForFile(dir+`\done.marker`, 60*time.Second) {
		fmt.Fprintln(os.Stderr, "thread spawner: the coordinator never wrote done.marker")
		return middleBroke | 13
	}
	return 0
}

// threadProber asks both doors of each named thread and writes one line per
// ask to answerFile -- "tid door answer" -- ending on 0 when every ask came
// back definite (open or denied), 1 when any ask answered with something
// else or could not be written down, 2 when it was given nothing it could
// run on. It is started by the coordinator under a RESTRICTED token, and
// being a separate process is the whole point: on an elevated desktop the
// test process's own token carries the Administrators group enabled, the
// locking list grants that group everything, and asked from in here every
// door would answer open -- a measurement that would lie about the shield.
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
// so it ends the test.
func readAnswers(t *testing.T, path string) []threadAnswer {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var answers []threadAnswer
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("the thread prober wrote an answer the test cannot read: %q", line)
		}
		id, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			t.Fatalf("the thread prober wrote an answer the test cannot read: %q: %v", line, err)
		}
		answers = append(answers, threadAnswer{id: uint32(id), door: fields[1], answer: fields[2]})
	}
	return answers
}

// makeAnswerFile creates the prober's answer file and writes onto it a
// permission list naming this account, because creating it was measured not
// to be enough. A file here inherits the directory's list, and the write the
// prober needs is granted that list by way of a group its token carries
// normally but does not carry restricted -- Authenticated Users, on this
// machine -- and a restricted token has to pass the check twice, once with
// each, so the prober's first open came back ACCESS_DENIED before it had
// asked a single door. The token's default list never enters into it: where
// the parent directory carries entries to inherit, they are the list a new
// file gets, whatever default the creating token holds.
//
// Naming the account itself is what reaches the prober's seat, because
// AsSandbox puts the account in the restricting list as well as the normal
// one -- the same reason the prowler can open an object whose list names the
// account. Protected, so nothing the directory grants is silently added
// back.
func makeAnswerFile(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	me, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	dacl, free, err := listAllowing(me)
	if err != nil {
		t.Fatal(err)
	}
	defer free()
	if r, _, callErr := procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, dacl, 0); r != 0 {
		t.Fatalf("giving the prober's restricted seat a write of its own on the answer file: error %d (%v)", r, callErr)
	}
}

// waitForTwoThreadIds waits for the spawner's ready marker to hold two thread
// ids, which is not the same as waiting for the file: os.WriteFile creates the
// file and writes into it afterwards, so a reader that moved on at the first
// sight of it read "" where it wanted two ids -- measured, under the race
// detector, where the loaded machine widened the window enough for the
// coordinator to lose the race the spawner's write was otherwise guaranteed to
// win. Every use of the marker wants the two ids, so the wait is for the two
// ids. An unparsable read -- empty or half-landed -- is not an answer, only a
// reason to look again before the deadline runs out.
func waitForTwoThreadIds(path string, timeout time.Duration) (t15, t2 uint64, ok bool) {
	deadline := time.Now().Add(timeout)
	for {
		if raw, err := os.ReadFile(path); err == nil {
			fields := strings.Fields(string(raw))
			if len(fields) == 2 {
				first, errFirst := strconv.ParseUint(fields[0], 10, 32)
				second, errSecond := strconv.ParseUint(fields[1], 10, 32)
				if errFirst == nil && errSecond == nil {
					return first, second, true
				}
			}
		}
		if time.Now().After(deadline) {
			return 0, 0, false
		}
		time.Sleep(20 * time.Millisecond)
	}
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
// reasons about, in a process this test owns, and both doors asked from
// outside afterwards. Three threads, three claims:
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
// taken from.
//
// A stand-in process stands in because a console host cannot be made to
// spawn a thread at a chosen moment from outside -- injecting one would need
// the very doors the shield closes -- the way race_test.go stands in for the
// stub. The real host's every thread is measured by
// TestAConsoleHostShutToItsAccountIsClosedToARestrictedToken, whose prowler
// now asks all of them.
//
// The control half is what gives the shield half meaning: before anything is
// shielded, the same prober opens every door of the first thread. A mutation
// that left any thread open -- a second thread passed over while the first
// was shut, a born-later thread given nothing, an ACCESS_DENIED refusal
// believed over a thread the list never reached -- turns this red, naming
// the thread and the door.
func TestAThreadBornIntoAShieldedProcessIsBornShut(t *testing.T) {
	dir := t.TempDir()
	t1File := dir + `\t1.marker`
	goFile := dir + `\go.marker`
	readyFile := dir + `\ready.marker`
	doneFile := dir + `\done.marker`

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var spawnerStderr bytes.Buffer
	cmd := exec.Command(exe, threadSpawnerFlag, dir)
	cmd.Stderr = &spawnerStderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Registered once the spawner exists, and run on the way out whatever
	// happened: killing something already gone is harmless, and a spawner
	// left holding its threads holds the test binary open.
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	if !waitForPid(t1File, 30*time.Second) {
		t.Fatalf("the thread spawner never wrote its first thread; its stderr: %s", spawnerStderr.String())
	}
	raw, err := os.ReadFile(t1File)
	if err != nil {
		t.Fatal(err)
	}
	t1, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		t.Fatalf("reading the first thread's id from %s: %v", t1File, err)
	}

	restricted, err := token.AsSandbox(nobodysGroup, "")
	if err != nil {
		t.Fatal(err)
	}
	defer restricted.Close()

	// Control: before anything is shielded, the same seat opens both doors of
	// the first thread. Without this, a refusal below would also be what a
	// broken build answers, and would prove nothing.
	beforeAnswers := dir + `\answers-before.marker`
	makeAnswerFile(t, beforeAnswers)
	line := syscall.EscapeArg(exe) + " " + threadProberFlag + " " + syscall.EscapeArg(beforeAnswers) + " " +
		strconv.FormatUint(t1, 10)
	code, err := Run(restricted, line, dir)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("the doors were shut before anything was shielded, so the refusals below would prove nothing: prober exit %d", code)
	}
	before := readAnswers(t, beforeAnswers)
	if len(before) != 2 {
		t.Fatalf("the prober answered %d asks about a process with one thread and two doors: %v", len(before), before)
	}
	for _, ask := range before {
		if ask.id != uint32(t1) || ask.answer != "open" {
			t.Fatalf("the doors were shut before anything was shielded, so the refusals below would prove nothing: thread %d door %s answered %s",
				ask.id, ask.door, ask.answer)
		}
	}

	// Let the spawner through the shield's three steps, now that the control
	// has been measured against the unshielded first thread.
	if err := os.WriteFile(goFile, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	t15, t2, ok := waitForTwoThreadIds(readyFile, 30*time.Second)
	if !ok {
		t.Fatalf("the thread spawner never reported the threads it was holding; its stderr: %s", spawnerStderr.String())
	}
	labels := map[uint32]string{
		uint32(t1):  "the thread born before anything was shielded",
		uint32(t15): "the thread born between the token's default list and the walk",
		uint32(t2):  "the thread born after the walk, carrying only the token's default list",
	}

	// Shield: all three threads, both doors, from the same seat. Exit 0 says
	// every ask came back definite; what the answers say is judged below.
	afterAnswers := dir + `\answers-after.marker`
	makeAnswerFile(t, afterAnswers)
	line = syscall.EscapeArg(exe) + " " + threadProberFlag + " " + syscall.EscapeArg(afterAnswers) + " " +
		strconv.FormatUint(t1, 10) + " " + strconv.FormatUint(t15, 10) + " " + strconv.FormatUint(t2, 10)
	code, err = Run(restricted, line, dir)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("the prober could not answer the shielded process's thread doors, so what it did answer is not evidence: exit %d", code)
	}
	after := readAnswers(t, afterAnswers)
	asked := map[string]bool{}
	for _, ask := range after {
		asked[ask.door+" "+strconv.FormatUint(uint64(ask.id), 10)] = true
		switch ask.answer {
		case "denied":
			// The door held. This is the measurement.
		case "open":
			t.Errorf("%s (%d) opened %s from the restricted seat after the shield", labels[ask.id], ask.id, ask.door)
		default:
			t.Errorf("%s (%d) could not be answered on %s: %s -- the thread is held alive on an event, so a vanished thread here is not a race, it is a measurement that failed",
				labels[ask.id], ask.id, ask.door, ask.answer)
		}
	}
	for id, what := range labels {
		for _, door := range []string{"redirect", "writeDac"} {
			if !asked[door+" "+strconv.FormatUint(uint64(id), 10)] {
				t.Fatalf("the prober never answered %s on %s (%d), so the shield was measured on less than it must hold for", door, what, id)
			}
		}
	}

	// The measurement is in; release the spawner, then read how its own steps
	// went -- a middleBroke ordinal there is the choreography failing, and
	// the answers above say nothing on their own.
	if err := os.WriteFile(doneFile, []byte("done"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	if waitErr == nil {
		return
	}
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		t.Fatalf("waiting for the thread spawner: %v; its stderr: %s", waitErr, spawnerStderr.String())
	}
	if broke := exitErr.ExitCode(); broke&middleBroke != 0 {
		t.Fatalf("the thread spawner failed on its own terms: %d; its stderr: %s", broke&^middleBroke, spawnerStderr.String())
	}
	t.Fatalf("the thread spawner ended on %d; its stderr: %s", exitErr.ExitCode(), spawnerStderr.String())
}
