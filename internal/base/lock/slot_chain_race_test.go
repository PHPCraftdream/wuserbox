// The ordering half of the crash story, measured at the level that matters:
// executable code. slot_chain_test.go holds the tree ending and the
// nothing-inherited fact; this file holds what is true at the first grant
// after the outer is killed outright.
package lock

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestTheProgramCannotRunWhenTheSlotIsGranted asserts the fact the lease
// actually buys: at the first successful grant after the outer of the chain
// is killed, the program of the chain cannot execute code. The program of
// the chain here is a heartbeat -- a loop stamping a monotonic sequence
// number and a QueryPerformanceCounter tick into a shared page a few
// hundred times a second -- so whether it ran one instruction after the
// grant is a comparison of two ticks of one machine-wide clock, and the
// program stamps its own beats, so nothing depends on when the test reads
// the page. A quiet page at the grant, settled long past the instrument's
// worst healthy pause, is the pass; a single beat at or after the grant
// instant is the fail.
//
// Two earlier instruments were replaced, and both histories are worth
// keeping so nobody "fixes" the assertion back.
//
// The first asked the question of the process object and failed: a process
// releases its handles before its process object signals, so for whoever
// holds the slot last, "the slot is free while the object is unsignaled" is
// a tautology, not a defect. That form failed 20 runs out of 20 on both
// sides of an experiment, and no arrangement of handles inside the dying
// tree can ever pass it.
//
// The second counted the program's live threads (Toolhelp snapshot plus
// WaitForSingleObject(handle, 0) per thread) and passed on "at most one",
// calling the survivor the exit's reaper which never returns to user mode.
// That instrument could not say what it claimed: WaitForSingleObject
// reports only signal state, and a signaled-or-not answer cannot tell a
// reaper that will never run again from a runnable thread parked in a wait
// -- and the program at the end of the chain was time.Sleep(60s), a
// process full of Go runtime threads parked in waits, so its thread count
// said almost nothing about whether it could execute code. Worse, when the
// grant landed between two thread samples the test logged "proves neither
// order" and returned green: a branch that establishes nothing must not
// pass.
//
// The numbers, measured with the heartbeat in this worktree over 20
// consecutive runs of this test on a machine under concurrent agent load:
// grants landed 0.76-46.4ms after the kill -- sixteen of the twenty inside
// 1.0-1.6ms, the tail being load spikes, not a property of the teardown;
// the heartbeat ran ~5000 beats per second (209 in the one run a concurrent
// build crushed the machine, still forty times the 40-beat health floor in
// chainRequireHealthyBeat); the worst pause between consecutive beats in a
// health window was 66.5ms, which is why the settle waits up to a second
// rather than a fixed bound; and in every run the program's last beat
// preceded the grant by 0.4-605ms -- the wide tail is the writer being
// descheduled, which the stamps absorb, since a beat that late would have
// carried a stamp after the grant -- and no beat ever landed at or after
// one, the settle re-read finding the sequence unchanged every time. The
// negative control,
// TestADetectorForTheGrantGoesRedWhenTheSlotIsReleasedEarly, arranges the
// slot coming free while the program beats and shows this verdict fires:
// in 6 consecutive runs the program's last beat landed 99.8-100.9ms after
// the slot came free, with the program still beating the whole time.
func TestTheProgramCannotRunWhenTheSlotIsGranted(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	name := fmt.Sprintf("wub-slot-race-%d", os.Getpid())
	beat := fmt.Sprintf("wub-slot-beat-race-%d", os.Getpid())
	dir := t.TempDir()
	ready := dir + `\chain.ready`
	t.Setenv(slotChainNameEnv, name)
	t.Setenv(slotChainReadyEnv, ready)
	t.Setenv(slotChainFlagsEnv, dir+`\chain.flags`)
	t.Setenv(slotChainBeatEnv, beat)

	// The section must exist before the program starts, because the program
	// opens it by name the moment it runs.
	base := chainOpenBeatPage(t, beat)
	outerPID, _, _ := chainSpawnForBeatTest(t, ready)

	// Load-bearing before the kill: it rules out a red result meaning a typo
	// in the slot name rather than an ordering failure.
	if _, err := Lease(name, 0); !errors.Is(err, ErrSlotHeld) {
		t.Fatalf("the chain's slot was not held before the kill: %v", err)
	}
	beatsPerSecond, maxGap := chainRequireHealthyBeat(t, base)
	t.Logf("the instrument before the kill: %d beats in %s (%d/s), worst gap %s",
		beatsPerSecond, chainBeatHealthWindow, beatsPerSecond*1000/int(chainBeatHealthWindow/time.Millisecond), maxGap)

	killed := time.Now()
	killSlotProcess(outerPID)
	// The loop begins at the kill instant, not after cmd.Wait(): the race is
	// between the slot coming free and the program's teardown, so anything
	// that waits first measures the teardown after it is over. The first
	// second is hammered attempt by attempt, because the whole window is
	// narrower than any poll interval worth naming.
	attempt := 0
	for {
		release, err := Lease(name, 0)
		if err == nil {
			defer release()
			break
		}
		if !errors.Is(err, ErrSlotHeld) {
			t.Fatal(err)
		}
		attempt++
		if time.Now().After(killed.Add(15 * time.Second)) {
			t.Fatalf("the lease was never granted within 15s of the kill, so the teardown left the slot held past the program's death or the program never died")
		}
		if time.Since(killed) > time.Second {
			time.Sleep(slotPoll)
		}
	}
	grant := chainQPCTicks()
	grantAfterKill := time.Since(killed)

	// The verdict. The program stamps its own beats, so beats that landed
	// between the grant and this read are still dated correctly: stamp at
	// or after the grant means code executed after the slot came free.
	seq, lastStamp := chainLastBeat(base)
	if lastStamp >= grant {
		t.Fatalf("the slot was granted %v after the kill (attempt %d) and the program's last beat lands %s AFTER the grant -- the program of the sandbox executed code while the slot was free (%d beats so far, instrument worst gap %s)",
			grantAfterKill, attempt, chainTicksToDuration(lastStamp-grant), seq/2, maxGap)
	}

	// Settle before believing the quiet page: wait twenty times the worst
	// healthy gap this run actually measured (bounded 50ms-1s; the measured
	// worst writer pause under load was 589ms, and the teardown that must
	// beat the settle -- cascade killing the program after the grant --
	// completes in ~1ms), then require
	// the sequence unchanged -- no beat anywhere after the pre-settle read,
	// whose stamp is already known to precede the grant.
	settle := maxGap * chainBeatSettleFactor
	if settle < 50*time.Millisecond {
		settle = 50 * time.Millisecond
	}
	if settle > time.Second {
		settle = time.Second
	}
	time.Sleep(settle)
	seqAfter, _ := chainLastBeat(base)
	if seqAfter != seq {
		t.Fatalf("a beat landed during the %s settle after a grant at which the program looked quiet -- the instrument cannot resolve this machine: %d beats before, %d after (worst gap %s)",
			settle, seq/2, seqAfter/2, maxGap)
	}
	t.Logf("the pass: grant %v after the kill (attempt %d), last beat %s BEFORE the grant, %d beats so far, %d beats/s, worst gap %s, settle %s found no further beat",
		grantAfterKill, attempt, chainTicksToDuration(grant-lastStamp), seq/2, beatsPerSecond, maxGap, settle)
}
