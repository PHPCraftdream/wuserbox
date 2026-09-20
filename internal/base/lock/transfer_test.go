package lock

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestAHandlePassedToThisProcessArrivesUsable pins what separates this
// handoff from the lease's: the duplicate arrives carrying real read access.
// PassTo's duplicate is handed over with desired access zero and is measured
// powerless over the slot file on purpose, because a lease's exclusion lives
// in a share mode and the access itself was the measured hazard. The handle
// this path hands over is a pipe read end the stub must ReadFile, so it must
// carry its access, and the proof is reading a byte through the adopted
// handle -- a duplicate that arrived powerless, the way a lease's must, is
// caught exactly here and nowhere earlier.
//
// The target is this same process, which exercises the identical API shape;
// the cross-process form is the lease's, already measured elsewhere.
func TestAHandlePassedToThisProcessArrivesUsable(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	transfer, cleanup, err := PrepareHandleTransfer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	if err := PassHandleTo(syscall.Handle(r.Fd()), current, transfer); err != nil {
		t.Fatalf("duplicating the pipe's read end into this process: %v", err)
	}
	handle, release, err := AdoptTransfer(transfer)
	if err != nil {
		t.Fatalf("a handoff this process wrote to itself did not parse: %v", err)
	}
	t.Cleanup(release)

	// Reading the byte is the whole point: DUPLICATE_SAME_ACCESS is not
	// paperwork, it is what makes the adopted handle able to ReadFile at
	// all, and the zero-access duplicate -- the lease's deliberate shape --
	// is the thing this read would catch.
	adopted := os.NewFile(uintptr(handle), "adopted-pipe-read-end")
	if _, err := w.Write([]byte{0xA5}); err != nil {
		t.Fatal(err)
	}
	saw := make([]byte, 1)
	if _, err := adopted.Read(saw); err != nil {
		t.Fatalf("the adopted handle could not read what was written beside it: %v", err)
	}
	if saw[0] != 0xA5 {
		t.Fatalf("the adopted handle read %#x back where %#x was written", saw[0], byte(0xA5))
	}

	// Letting go twice must do nothing the second time, and the cleanup
	// must have taken the file with it: both are the guarantees the lease
	// handoff gives, arrived at through this path.
	release()
	release()
	cleanup()
	if _, err := os.Stat(transfer); !os.IsNotExist(err) {
		t.Fatalf("the handoff file survived its own cleanup: %v", err)
	}
}

// TestAdoptTransferRefusesGarbage meets the parse where its callers meet it:
// through the file, read back by a process that had no part in writing it.
// A handoff file that is missing was cleaned up before its reader got there,
// or was never written; one holding text holds what a failed or truncated
// handoff leaves; one holding zero holds the value that says no handle
// arrived at all. All three must come back as errors rather than as
// handles, because the close these functions return is attached to a number,
// and closing a number closes whatever holds it now.
func TestAdoptTransferRefusesGarbage(t *testing.T) {
	if _, _, err := AdoptTransfer(filepath.Join(t.TempDir(), "never-written")); err == nil {
		t.Fatal("adopting a handoff file that was never written succeeded")
	}
	for _, value := range []string{"not-a-handle", "0"} {
		path := filepath.Join(t.TempDir(), "handoff")
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := AdoptTransfer(path); err == nil {
			t.Fatalf("adopting a handoff file holding %q succeeded", value)
		}
	}
}
