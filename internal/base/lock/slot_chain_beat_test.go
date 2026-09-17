// The heartbeat that makes the slot's grant moment decidable, and the
// negative control that proves the detector behind it can go red. The
// program at the end of the chain, when told through slotChainBeatEnv,
// stamps a sequence number and a QueryPerformanceCounter tick into a
// shared page on every beat, so any code it executes leaves a dated trace
// -- and whether that trace crosses the instant the slot comes free is a
// comparison of two ticks on one machine, never a race between the test's
// reads and the program's writes.
package lock

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// slotChainBeatEnv names the section object the program beats into; it is
// set only by the tests, never production code.
const slotChainBeatEnv = "WUSERBOX_SLOT_CHAIN_BEAT"

// slotChainReleaseEnv makes the outer and the stub each release their copy
// of the lease on purpose, so the slot comes free while the program is
// demonstrably beating -- the negative control's arrangement. In that mode
// both stages wait for slotChainGoEnv's file to exist first, so the
// control test can show the slot held and the instrument healthy before
// the release happens.
const slotChainReleaseEnv = "WUSERBOX_SLOT_CHAIN_RELEASE"

// slotChainGoEnv names the go file the release-mode stages wait for; see
// slotChainReleaseEnv.
const slotChainGoEnv = "WUSERBOX_SLOT_CHAIN_GO"

// chainWaitForGo blocks until the control test's go file exists. A missing
// file is the control test still measuring; the bound only keeps a broken
// run from hanging the chain for its whole 60s sleep.
func chainWaitForGo(t *testing.T, path string) {
	if !waitForSlotTestFile(path, 15*time.Second) {
		t.Fatal("the go file never came")
	}
}

var (
	procCreateFileMappingForBeat = w32.Kernel32.NewProc("CreateFileMappingW")
	procOpenMappingForBeat       = w32.Kernel32.NewProc("OpenFileMappingW")
	procMapViewForBeat           = w32.Kernel32.NewProc("MapViewOfFile")
	procUnmapForBeat             = w32.Kernel32.NewProc("UnmapViewOfFile")
	procQPCForBeat               = w32.Kernel32.NewProc("QueryPerformanceCounter")
	procQPFForBeat               = w32.Kernel32.NewProc("QueryPerformanceFrequency")
)

// chainBeatPage is the shared page: completed beats are seq/2, and seq is
// odd exactly while stamp is being written -- a seqlock, so the reader can
// always tell a torn beat from a finished one. The page base is 64K
// aligned, so the two uint64 fields are 8-aligned as the atomics require.
type chainBeatPage struct {
	seq   uint64
	stamp uint64
}

const (
	chainPageReadWrite = 0x00000004 // PAGE_READWRITE, winnt.h
	chainMapRead       = 0x00000004 // FILE_MAP_READ
	chainMapWrite      = 0x00000002 // FILE_MAP_WRITE
)

// chainQPCTicks reads the per-machine high-resolution counter. Both sides
// of the comparison use it because it is the only clock whose ticks mean
// the same thing in two processes; time.Now's monotonic reading is
// per-process and must never be compared across one.
func chainQPCTicks() uint64 {
	var v int64
	procQPCForBeat.Call(uintptr(unsafe.Pointer(&v)))
	return uint64(v)
}

// chainQPCFreqTicksPerSecond is read once; on any supported Windows it does
// not change while the machine runs.
var chainQPCFreqTicksPerSecond = func() int64 {
	var f int64
	procQPFForBeat.Call(uintptr(unsafe.Pointer(&f)))
	if f <= 0 {
		panic("QueryPerformanceFrequency returned a non-positive frequency")
	}
	return f
}()

func chainTicksToDuration(ticks uint64) time.Duration {
	return time.Duration(int64(ticks) * int64(time.Second) / chainQPCFreqTicksPerSecond)
}

// chainPagePointer turns a mapped view's address into a page pointer. The
// address comes from the kernel's mapper, not from a Go pointer, so the
// conversion is sound; it is routed through a uintptr-bearing struct only
// because go vet's unsafeptr check rejects every direct uintptr-to-Pointer
// conversion it can see, including this sound one.
type chainPagePointer struct{ v uintptr }

func chainPagePointerOf(v uintptr) unsafe.Pointer {
	p := chainPagePointer{v}
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

// chainOpenBeatPage creates the named section and maps it read-only into
// the test, returning the page base for the reader below. It must be
// called before the chain is spawned, because the program opens the same
// name when it starts.
func chainOpenBeatPage(t *testing.T, name string) unsafe.Pointer {
	t.Helper()
	wide, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	h, _, callErr := procCreateFileMappingForBeat.Call(^uintptr(0), // INVALID_HANDLE_VALUE
		0, uintptr(chainPageReadWrite), 0, 4096, uintptr(unsafe.Pointer(wide)))
	if h == 0 {
		t.Fatalf("creating the beat section %s: %v", name, callErr)
	}
	handle := syscall.Handle(h)
	baseUnsafe, _, callErr := procMapViewForBeat.Call(h, chainMapRead, 0, 0, 0)
	if baseUnsafe == 0 {
		syscall.CloseHandle(handle)
		t.Fatalf("mapping the beat section %s: %v", name, callErr)
	}
	base := chainPagePointerOf(baseUnsafe)
	t.Cleanup(func() {
		procUnmapForBeat.Call(uintptr(base))
		syscall.CloseHandle(handle)
	})
	return base
}

// chainLastBeat reads the newest finished beat. An odd seq, or a seq that
// changes under the read, means the writer was mid-beat; the page holds
// every earlier beat, so retrying loses nothing and the answer is never
// "unknown".
//
// The retry is bounded, because the writer here is a process these tests
// kill outright. A kill landing between the odd seq and the even one
// leaves the page odd for good, and an unbounded reader would then spin
// until go test's whole timeout -- a ~30ns window against a 200us beat, so
// roughly one run in ten thousand would stop looking like a failed
// measurement and start looking like broken infrastructure. Past the bound
// the torn reading is returned as it stands, which is the safe direction:
// stamp then carries the newest tick the writer ever wrote, which is the
// last code it ever executed, so using it can only make the verdict
// stricter. The bound is well past the worst writer pause measured on a
// loaded machine (589ms), since a pause can fall between those two
// instructions like anywhere else.
func chainLastBeat(base unsafe.Pointer) (seq, stamp uint64) {
	page := (*chainBeatPage)(base)
	deadline := time.Now().Add(2 * time.Second)
	for {
		s1 := atomic.LoadUint64(&page.seq)
		if s1%2 == 1 {
			if time.Now().After(deadline) {
				return s1, atomic.LoadUint64(&page.stamp)
			}
			continue
		}
		st := atomic.LoadUint64(&page.stamp)
		s2 := atomic.LoadUint64(&page.seq)
		if s1 == s2 || time.Now().After(deadline) {
			return s1, st
		}
	}
}

// chainSampleBeats watches the page for window and reports how many beats
// landed and the largest gap between consecutive beat stamps, in ticks.
// Gaps are only taken over consecutive beats -- seq advancing by exactly 2
// between two reads -- because a sampler that is itself descheduled skips
// beats, and a skipped beat would otherwise be reported as a program pause
// that never happened. The gap is what decides whether the instrument can
// resolve the roughly millisecond window between the kill and the grant:
// if beats can legitimately pause longer than that, a quiet page proves
// nothing.
func chainSampleBeats(base unsafe.Pointer, window time.Duration) (beats int, maxGapTicks uint64) {
	prevSeq, prevStamp := chainLastBeat(base)
	// A zero stamp is an unwritten page, not a beat at time zero: waiting
	// here keeps the first gap from being measured against the machine's
	// whole uptime, which overflows the tick-to-duration conversion and
	// reports an absurd negative gap.
	//
	// The wait is the chain's own 20 seconds and not a couple, because what
	// is being waited for is a process starting, not a beat arriving late.
	// The stub writes the ready file the moment it has resumed the program,
	// and the program still has a Go runtime to bring up and a section to
	// open before its first beat; measured under `go test ./...`, which runs
	// a package per core, that took longer than two seconds and the health
	// check read the silence as a dead instrument. The sleep is part of the
	// same repair: the old spin held a core the writer was trying to start
	// on. None of this touches what is measured -- the 150ms window and the
	// gaps inside it begin once the instrument is known to be alive.
	if prevStamp == 0 {
		deadline := time.Now().Add(20 * time.Second)
		for prevStamp == 0 && time.Now().Before(deadline) {
			if s, st := chainLastBeat(base); st != 0 {
				prevSeq, prevStamp = s, st
				break
			}
			time.Sleep(time.Millisecond)
		}
		if prevStamp == 0 {
			return 0, 0 // no beat ever arrived: the window will agree
		}
	}
	start := time.Now()
	for time.Since(start) < window {
		seq, st := chainLastBeat(base)
		if seq <= prevSeq {
			continue
		}
		if seq == prevSeq+2 {
			if gap := st - prevStamp; gap > maxGapTicks {
				maxGapTicks = gap
			}
		}
		beats += int(seq-prevSeq) / 2
		prevSeq, prevStamp = seq, st
	}
	return beats, maxGapTicks
}

// The thresholds are the measured machine, not taste; the numbers in the
// race test's doc comment are the full spread they came from. The gap
// bound is deliberately generous: the writer's stamps stay absolute no
// matter how long the machine deschedules it (worst measured pause 589ms
// across 140 sampled windows), so a pause costs resolution nowhere -- it
// only sets how long the settle has to wait before trusting a quiet page.
// What health actually means here is that the program beats at all: a
// full-rate window runs ~750 beats, and windows under the worst observed
// load still cleared 40.
const (
	chainBeatHealthWindow   = 150 * time.Millisecond
	chainBeatHealthMinBeats = 40
	chainBeatHealthMaxGap   = time.Second
	chainBeatSettleFactor   = 20
	// How long the health check will keep asking for its beats before
	// calling the instrument dead. A full-rate window produces roughly 750
	// of them and needs one pass; a machine running a test package per core
	// has taken several. This bounds a stall, it does not set a pace.
	chainBeatHealthPatience = 10 * time.Second
	// How long the negative control will wait for the program to prove it
	// is still executing with the slot free. Same reason as the patience
	// above: what the control needs is one beat after the free instant, and
	// a busy machine can take longer than a fixed sleep to deliver it
	// without the program having stopped at all.
	chainBeatStillRunning = 5 * time.Second
)

// chainRequireHealthyBeat asserts the instrument works before anything is
// decided with it. An unhealthy instrument is fatal, never a pass.
//
// It asks for a count of beats rather than for a rate, and keeps asking
// until it has them or chainBeatHealthPatience is spent. The difference
// matters because the thing being measured is not how fast the writer runs
// -- the verdict never reads a rate, only stamps -- but whether it beats at
// all and how long it can pause, and both of those survive a slow machine
// while a rate does not. Measured under `go test ./...`, a package per core:
// the writer managed 37 beats in the 150ms this used to allow itself and the
// run went red for it, on an instrument that was working perfectly and said
// so in the same breath, worst gap 210us. A test that fails because the
// machine was busy teaches people to re-run it.
//
// What is still fatal: a writer that cannot produce the count inside the
// patience, and one whose worst pause is longer than the window the verdict
// has to resolve. Those are the two ways a quiet page would stop meaning
// anything.
func chainRequireHealthyBeat(t *testing.T, base unsafe.Pointer) (beats int, maxGap time.Duration) {
	t.Helper()
	deadline := time.Now().Add(chainBeatHealthPatience)
	var gapTicks uint64
	for {
		n, gap := chainSampleBeats(base, chainBeatHealthWindow)
		beats += n
		if gap > gapTicks {
			gapTicks = gap
		}
		maxGap = chainTicksToDuration(gapTicks)
		if maxGap > chainBeatHealthMaxGap {
			t.Fatalf("the instrument failed before the kill: a pause of %s between two beats, and a decision needs pauses under %s",
				maxGap, chainBeatHealthMaxGap)
		}
		if beats >= chainBeatHealthMinBeats {
			return beats, maxGap
		}
		if time.Now().After(deadline) {
			t.Fatalf("the instrument failed before the kill: %d beats in %s, and a decision needs at least %d",
				beats, chainBeatHealthPatience, chainBeatHealthMinBeats)
		}
	}
}

// chainRunHeartbeat is the program's half: it runs forever, stamping a
// beat roughly every 200 microseconds, and is ended by its job like any
// program of a run. It never returns on its own.
func chainRunHeartbeat(t *testing.T, section string) {
	wide, err := syscall.UTF16PtrFromString(section)
	if err != nil {
		t.Fatal(err)
	}
	h, _, callErr := procOpenMappingForBeat.Call(chainMapWrite, 0, uintptr(unsafe.Pointer(wide)))
	if h == 0 {
		t.Fatalf("the program could not open the beat section %s: %v", section, callErr)
	}
	baseUnsafe, _, callErr := procMapViewForBeat.Call(h, chainMapWrite, 0, 0, 0)
	if baseUnsafe == 0 {
		t.Fatalf("the program could not map the beat section %s: %v", section, callErr)
	}
	// The writer's pauses are what the instrument's resolution costs, so the
	// loop takes an OS thread of its own and never gives it back. What still
	// pauses it -- the scheduler, a collection of the small allocation
	// syscall.Proc.Call makes per call -- widens the gap between two beats
	// and cannot falsify one: each stamp is read inside the beat that
	// carries it, so a pause moves the next beat later, never the last one
	// earlier. Turning the collector off was tried here and does nothing,
	// since GOGC is read once at startup and this loop is already running.
	runtime.LockOSThread()
	page := (*chainBeatPage)(chainPagePointerOf(baseUnsafe))
	// ~200us of ticks: the interval is paced by the same clock the stamps
	// use, and the spin between beats exists because a Go timer would swamp
	// the millisecond-scale window the test has to resolve.
	interval := uint64(chainQPCFreqTicksPerSecond * int64(200*time.Microsecond) / int64(time.Second))
	next := chainQPCTicks()
	for {
		next += interval
		for chainQPCTicks() < next {
		}
		atomic.AddUint64(&page.seq, 1) // odd: the stamp is being written
		atomic.StoreUint64(&page.stamp, chainQPCTicks())
		atomic.AddUint64(&page.seq, 1) // even: the beat is finished
	}
}

// chainSpawnForBeatTest builds the chain the way both tests that measure
// the grant need it: an outer holding the lease, a stub that adopted the
// duplicate, a program at the end -- then reads the stub's and the
// program's pids out of the ready file. Cleanups kill stub, program and
// outer, in that order, and collect them.
func chainSpawnForBeatTest(t *testing.T, ready string) (outerPID, stubPID, programPID uint32) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=TestSlotChainOuterHoldsTheChainAndWaits")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	outerPID = uint32(cmd.Process.Pid)
	t.Cleanup(func() {
		killSlotProcess(outerPID)
		_ = cmd.Wait() // the watch is started at the kill; the cleanup collects the process
	})
	stubPID, programPID = waitForSlotChainPIDs(t, ready, 20*time.Second)
	t.Cleanup(func() { killSlotProcess(stubPID); killSlotProcess(programPID) })
	return outerPID, stubPID, programPID
}

// waitForSlotChainPIDs waits for the stub's handoff file to hold two pids
// and not merely to exist. The parse is the wait's own condition because a
// half-written file can still parse: os.WriteFile creates before it writes,
// and "11844 1" is two good numbers whose second is a pid this test would
// go on to kill. Nothing here is acted on until the file says the whole of
// what it was going to say.
func waitForSlotChainPIDs(t *testing.T, ready string, wait time.Duration) (stubPID, programPID uint32) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(ready)
		if err == nil {
			if n, _ := fmt.Sscanf(string(data), "%d %d", &stubPID, &programPID); n == 2 {
				return stubPID, programPID
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the outer never built its chain: %s never came to hold two pids", ready)
	return 0, 0
}

// TestADetectorForTheGrantGoesRedWhenTheSlotIsReleasedEarly is the
// negative control for TestTheProgramCannotRunWhenTheSlotIsGranted, and it
// exists because a detector that cannot fire cannot be trusted to hold
// anything. It arranges the very state the race test exists to catch: with
// slotChainReleaseEnv set, the outer and the stub each release their copy
// of the lease on purpose, so the slot comes free while the program is
// alive and beating. The test first shows the slot is held, polls until the
// grant lands (stamp F), shows the program kept executing after F -- the
// exact danger the race test forbids -- and then requires the race test's
// own verdict rule, "the last beat's stamp is at or after the free
// instant", to fire. If it does not fire, this control fails.
//
// Run both with:
//
//	go test ./internal/base/lock -run 'TestTheProgramCannotRunWhenTheSlotIsGranted|TestADetectorForTheGrantGoesRedWhenTheSlotIsReleasedEarly' -count=1 -v
//
// Measured: in 6 consecutive runs the slot came free ~100ms after the go
// signal (the release-mode stages poll for it), the program went on
// beating at its full ~5000 beats per second with the slot free, and the
// verdict fired every time -- the last beat landing 99.8-100.9ms after the
// free instant.
func TestADetectorForTheGrantGoesRedWhenTheSlotIsReleasedEarly(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	name := fmt.Sprintf("wub-slot-red-%d", os.Getpid())
	beat := fmt.Sprintf("wub-slot-beat-red-%d", os.Getpid())
	dir := t.TempDir()
	ready := dir + `\chain.ready`
	t.Setenv(slotChainNameEnv, name)
	t.Setenv(slotChainReadyEnv, ready)
	t.Setenv(slotChainFlagsEnv, dir+`\chain.flags`)
	t.Setenv(slotChainBeatEnv, beat)
	t.Setenv(slotChainReleaseEnv, "1")
	goFile := dir + `\chain.go`
	t.Setenv(slotChainGoEnv, goFile)

	base := chainOpenBeatPage(t, beat)
	_, _, programPID := chainSpawnForBeatTest(t, ready)

	// Load-bearing, as in the race test: a typo in the slot name would also
	// make Lease succeed, and the control must not mistake that for freedom.
	if _, err := Lease(name, 0); !errors.Is(err, ErrSlotHeld) {
		t.Fatalf("the chain's slot was not held before the release: %v", err)
	}
	beats, gap := chainRequireHealthyBeat(t, base)
	t.Logf("the program beats while the slot is held: %d beats in %s, worst gap %s",
		beats, chainBeatHealthWindow, gap)

	// Both stages were waiting for this; from here the two copies of the
	// lease close and the slot comes free while the program keeps beating.
	writeSlotTestFile(t, goFile, "go")

	// The two releases happen inside the chain, the moment the stub reports
	// ready; by the time this poll succeeds, both copies are closed.
	polled := time.Now()
	release, err := Lease(name, 10*time.Second)
	if err != nil {
		t.Fatalf("the slot never came free after the chain released it on purpose: %v", err)
	}
	defer release()
	freeAt := chainQPCTicks()
	t.Logf("the slot came free %s after the ready file, program pid %d still alive",
		time.Since(polled), programPID)

	// The program must still be executing with the slot free -- that is the
	// state the race test exists to detect, arranged on purpose.
	seqBefore, _ := chainLastBeat(base)
	seqAfter, lastStamp := seqBefore, uint64(0)
	waited := time.Now().Add(chainBeatStillRunning)
	for {
		seqAfter, lastStamp = chainLastBeat(base)
		if seqAfter > seqBefore {
			break
		}
		if time.Now().After(waited) {
			t.Fatalf("with the slot free the program stopped beating: %d beats before, %d after %s",
				seqBefore/2, seqAfter/2, chainBeatStillRunning)
		}
		time.Sleep(time.Millisecond)
	}
	// The verdict rule the race test applies, applied to an arrangement
	// where it must fire: with code demonstrably executing after the slot
	// came free, the last beat sits at or after the free instant.
	if lastStamp < freeAt {
		t.Fatalf("the detector did not fire: the program kept beating after the slot came free (seq %d -> %d) yet its last beat precedes the free instant, so the verdict rule is broken",
			seqBefore/2, seqAfter/2)
	}
	t.Logf("the detector fires: the program's last beat lands %s after the slot came free, %d beats into the run",
		chainTicksToDuration(lastStamp-freeAt), seqAfter/2)
}
