package proc

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// ownToken runs a command under this process's own token, which exercises
// everything except the restriction itself.
func ownToken(t *testing.T) syscall.Token {
	t.Helper()
	var self syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &self); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { self.Close() })
	return self
}

func TestRunReportsTheExitCode(t *testing.T) {
	dir := t.TempDir()
	for _, want := range []int{0, 3} {
		code, err := Run(ownToken(t), `C:\Windows\System32\cmd.exe /c exit `+itoa(want), dir)
		if err != nil {
			t.Fatal(err)
		}
		if code != want {
			t.Errorf("exit code %d, want %d", code, want)
		}
	}
}

func TestRunUsesTheGivenDirectory(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "here.txt")
	if _, err := Run(ownToken(t), `C:\Windows\System32\cmd.exe /c echo here>here.txt`, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the command did not run in %s: %v", dir, err)
	}
}

func TestRunReportsAMissingProgram(t *testing.T) {
	if _, err := Run(ownToken(t), `C:\no-such-program.exe`, t.TempDir()); err == nil {
		t.Error("expected an error")
	}
}

func TestRunForwardsStandardStreams(t *testing.T) {
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		inRead.Close()
		inWrite.Close()
		t.Fatal(err)
	}
	errRead, errWrite, err := os.Pipe()
	if err != nil {
		inRead.Close()
		inWrite.Close()
		outRead.Close()
		outWrite.Close()
		t.Fatal(err)
	}
	defer inRead.Close()
	defer outRead.Close()
	defer errRead.Close()

	oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin, os.Stdout, os.Stderr = inRead, outWrite, errWrite
	defer func() {
		os.Stdin, os.Stdout, os.Stderr = oldIn, oldOut, oldErr
	}()
	if _, err := inWrite.WriteString("from-stdin\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := inWrite.Close(); err != nil {
		t.Fatal(err)
	}

	code, runErr := Run(ownToken(t), `C:\Windows\System32\cmd.exe /c "(more & echo stdout & echo stderr 1>&2)"`, t.TempDir())
	if err := outWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := errWrite.Close(); err != nil {
		t.Fatal(err)
	}
	stdout, stdoutErr := io.ReadAll(outRead)
	stderr, stderrErr := io.ReadAll(errRead)
	if runErr != nil {
		t.Fatal(runErr)
	}
	if code != 0 {
		t.Fatalf("stream probe ended with exit code %d", code)
	}
	if stdoutErr != nil {
		t.Fatal(stdoutErr)
	}
	if stderrErr != nil {
		t.Fatal(stderrErr)
	}
	if !strings.Contains(string(stdout), "from-stdin") || !strings.Contains(string(stdout), "stdout") {
		t.Errorf("stdout was %q, want stdin and stdout markers", stdout)
	}
	if !strings.Contains(string(stderr), "stderr") {
		t.Errorf("stderr was %q, want stderr marker", stderr)
	}
}

func TestOutputBridgeRelaysAStream(t *testing.T) {
	targetRead, targetWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer targetRead.Close()

	read, handle, err := bridgePipe("test")
	if err != nil {
		t.Fatal(err)
	}
	bridge := &outputBridge{stdoutRead: read, stdout: targetWrite}
	bridge.start()
	childWrite := os.NewFile(uintptr(handle), "bridge-child")
	if _, err := childWrite.WriteString("bridged output\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := childWrite.Close(); err != nil {
		t.Fatal(err)
	}
	bridge.finish()
	if err := targetWrite.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(targetRead)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "bridged output\r\n" {
		t.Fatalf("bridge returned %q", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}
