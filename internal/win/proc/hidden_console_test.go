package proc

// The close test for the console harness: takeAConsole's promise is that
// the four interrupt tests that take a console never put a console window
// on the screen -- not "hide it quickly", never put one there at all. This
// holds the harness to both halves of what that promise means, by
// observation rather than by construction:
//
//   - No window ever appears. A window that flashes and is hidden again
//     between two statements is exactly the race the old AllocConsole-then-
//     ShowWindow(SW_HIDE) harness lost, so the question is asked
//     continuously by a poller running before, during and after the
//     harness, not once at a moment of the harness's choosing.
//
//   - What was taken is a real console. A windowless thing that could not
//     deliver GenerateConsoleCtrlEvent would pass the first half while
//     quietly failing everything the interrupt tests exist to measure, so
//     the same windowless console carries one real CTRL_BREAK_EVENT to a
//     driver, and the program at the end of the chain says it arrived.
//
// What was learned the hard way about why the console is needed at all is
// in interrupt_test.go.

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestTakingAConsoleNeverPutsAWindowOnTheScreen(t *testing.T) {
	// Detached first, so the poller below starts from a known zero: `go
	// test` from a shell gives this process a console of its own, and until
	// it is freed GetConsoleWindow would answer with that shell's window
	// rather than with anything this harness did. GetConsoleWindow answers
	// 0 for a process attached to no console.
	procFreeConsole.Call()

	// The poller asks before takeAConsole's first statement and keeps asking
	// until told to stop, yielding rather than sleeping: a window on the
	// screen for even one scheduling quantum is a failure, and the race it
	// guards against was measured in single milliseconds. The channel is
	// buffered so the goroutine can never block the test; it sends the first
	// nonzero handle it ever sees and stops.
	stop := make(chan struct{})
	seen := make(chan uintptr, 1)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if window, _, _ := procGetConsoleWindow.Call(); window != 0 {
				seen <- window
				return
			}
			runtime.Gosched()
		}
	}()

	takeAConsole(t)
	close(stop)

	select {
	case window := <-seen:
		t.Fatalf("a console window was on the screen during the harness: handle 0x%x", window)
	default:
	}
	// And none afterwards either: the assert is on what the sequence left
	// behind, not on what takeAConsole says about itself.
	if window, _, _ := procGetConsoleWindow.Call(); window != 0 {
		t.Fatalf("GetConsoleWindow is 0x%x after taking a console; a windowless console was the whole point", window)
	}

	// The other half, against the same windowless console: a control event
	// delivered through it. The driver is the patient shape -- the program
	// at the end hears the event and carries on -- and the proof is the
	// .heard file the program writes when the event reaches it. One event,
	// once: this measures delivery, not insistence.
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "result.txt")
	pidFile := filepath.Join(dir, "grandchild.pid")

	cmd := driverCommand(t, "patient", dir, resultFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// In addition to driverCommand's own cleanup, in the same spirit: a test
	// that fails between here and the end cannot leave the driver behind.
	defer func() { _ = cmd.Process.Kill() }()
	if !waitForFile(filepath.Join(dir, "ready.marker"), 90*time.Second) {
		t.Fatal("the driver never became ready")
	}

	if r, _, callErr := procGenerateCtrlEvent.Call(ctrlBreakEvent, uintptr(cmd.Process.Pid)); r == 0 {
		t.Fatalf("GenerateConsoleCtrlEvent: %v", callErr)
	}
	if !waitForFile(heardFile(pidFile), 10*time.Second) {
		t.Error("the interrupt never reached the program: the windowless console does not deliver control events, and is not a console")
	}
}
