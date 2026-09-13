package exec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandLineResolvesAndQuotes(t *testing.T) {
	line, err := CommandLine([]string{"cmd", "/c", "echo hello world"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(line), "cmd.exe") {
		t.Errorf("argv[0] was not resolved to a full path: %q", line)
	}
	if !strings.Contains(line, `"echo hello world"`) {
		t.Errorf("argument with spaces was not quoted: %q", line)
	}
}

func TestCommandLineWrapsBatchFiles(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "build.bat")
	if err := os.WriteFile(script, []byte("@echo off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	line, err := CommandLine([]string{script, "arg"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.ToLower(line), "cmd.exe /c ") {
		t.Errorf("batch file not wrapped by the interpreter: %q", line)
	}
}

func TestCommandLineReportsMissingProgram(t *testing.T) {
	if _, err := CommandLine([]string{"no-such-program-wuserbox"}); err == nil {
		t.Error("expected an error for a program that is not on PATH")
	}
}
