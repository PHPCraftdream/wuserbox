package proc

import (
	"os"
	"path/filepath"
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
