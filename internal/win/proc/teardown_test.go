// The teardown order P1-2 asks for, measured on the mechanism it rests on:
// that a job whose kill-on-close is set ends the one process keeping a
// bridge pipe from EOF, and that the EOF arrives the moment the job closes.
// Closing the job before draining the bridge -- the reorder inside
// runAsAccount -- is what turns that mechanism into a run that comes back;
// this file measures the mechanism, because it can, anywhere, without the
// administrator rights and the real second account the full run needs. The
// full run is measured in internal/e2e's teardown_test.go.

package proc

import (
	"io"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestJobCloseEndsTheChildHoldingABridgeWriteEnd stands in for the shape
// P1-2 describes: a program has exited, a child it left behind still holds
// an inherited copy of the bridge's write end, and the only thing that will
// end the child -- the job's close -- is also the only thing that will let
// the bridge drain reach EOF. The child here is a real process, the pipe a
// real bridge pipe, and the close a real job close; what the test proves is
// that the two needs are one need, so ordering the close first costs
// nothing and ordering it last hangs the drain forever.
func TestJobCloseEndsTheChildHoldingABridgeWriteEnd(t *testing.T) {
	read, handle, err := bridgePipe("test")
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()

	j, err := newJob()
	if err != nil {
		t.Fatal(err)
	}

	// A child that holds the write end and stays alive: what a backgrounded
	// child is once its program has exited. It takes the handle the way a
	// shell's background job takes the shell's stdout -- by ambient
	// inheritance -- and writes nothing anywhere.
	var startup syscall.StartupInfo
	var created syscall.ProcessInformation
	startup.Cb = uint32(unsafe.Sizeof(startup))
	line, err := syscall.UTF16FromString(`C:\Windows\System32\cmd.exe /c ping -n 600 127.0.0.1 >nul`)
	if err != nil {
		t.Fatal(err)
	}
	const flags = createSuspended | createNoWindow
	r, _, callErr := procCreateProcessAsUser.Call(uintptr(ownToken(t)), 0,
		uintptr(unsafe.Pointer(&line[0])), 0, 0, 1, flags, 0, 0,
		uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&created)))
	runtime.KeepAlive(line)
	if r == 0 {
		t.Fatalf("starting the stand-in child: %v", callErr)
	}
	defer syscall.CloseHandle(created.Process)
	defer syscall.CloseHandle(created.Thread)
	// Runs first, before the closes above: a leftover ping would outlive
	// the test by ten minutes on any failure path that did not reach the
	// job's close, and a terminate against an already-dead child is a
	// harmless nothing.
	defer procTerminateProcess.Call(uintptr(created.Process), 1)
	if err := j.assign(created.Process); err != nil {
		t.Fatal(err)
	}
	// The parent's own copy closed while the child is still suspended,
	// exactly as closeStreams runs the moment the account process exists:
	// from here on the child is the only holder left, and EOF on the read
	// end is its death and nothing else.
	if err := syscall.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	procResumeThread.Call(uintptr(created.Thread))

	eof := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, read)
		eof <- err
	}()

	// The negative control, and the premise: while the job stands, the
	// drain does not come unstuck. If EOF arrives here, the child died on
	// its own or a handle this test believed closed is still held, and
	// nothing below would be measuring what it claims.
	select {
	case <-eof:
		t.Fatal("the bridge reached EOF while the child holding its write end was alive")
	case <-time.After(500 * time.Millisecond):
	}

	// The act the reorder adds, in the position the reorder puts it --
	// before anything waits on the bridge. Kill-on-close ends the child,
	// its write end dies with it, and the drain a real run would be waiting
	// in comes unstuck.
	j.Close()
	select {
	case err := <-eof:
		if err != nil {
			t.Fatalf("reading the bridge after the job closed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the bridge never reached EOF after the job closed")
	}
	if w, err := syscall.WaitForSingleObject(created.Process, 30000); w != syscall.WAIT_OBJECT_0 {
		t.Fatalf("the child outlived the job's close: %v", err)
	}
}
