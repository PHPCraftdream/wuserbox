package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
)

// needsReadGroup leaves a test unrun where group.ReadGroup was never created.
// Creating it needs administrator rights, the same as a sandbox's own group,
// so an unprivileged run of these tests has nowhere to get it from.
func needsReadGroup(t *testing.T) {
	t.Helper()
	if _, exists, err := group.Comment(group.ReadGroup); err != nil {
		t.Fatal(err)
	} else if !exists {
		t.Skip("wub-read does not exist yet; run `wuserbox --init` elevated once to cover profile reads")
	}
}

func TestReadsFilesTheCallerCanRead(t *testing.T) {
	box := newBox(t)
	// This file lives outside the sandbox and has no entry for its SID.
	secretish := filepath.Join(box.denied, "caller-owned.txt")
	if err := os.WriteFile(secretish, []byte("readable"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "type " + secretish})
}

func TestReadsTheUserProfile(t *testing.T) {
	needsReadGroup(t)
	box := newBox(t)
	mustSucceed(t, box.state, script(t, box, `dir /b "%USERPROFILE%" >nul`))
}

func TestStartsProgramsThatLoadTheWindowSubsystem(t *testing.T) {
	// Without Everyone among the restricting SIDs every process that loads
	// user32 dies at startup with 0xC0000142. This is the regression guard.
	box := newBox(t)
	mustSucceed(t, box.state, []string{`C:\Windows\System32\whoami.exe`})
}

func TestChildProcessesStayRestricted(t *testing.T) {
	box := newBox(t)
	script := filepath.Join(box.granted, "escape.cmd")
	target := filepath.Join(box.denied, "via-child.txt")
	body := "@echo off\r\ncmd.exe /c echo x>" + target + "\r\n"
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	mustFail(t, box.state, []string{script})
	if _, err := os.Stat(target); err == nil {
		t.Error("a child process wrote outside the sandbox")
		os.Remove(target)
	}
}

func TestTemporaryFilesLandInTheSandboxDirectory(t *testing.T) {
	box := newBox(t)
	mustSucceed(t, box.state, script(t, box, `echo x>"%TEMP%\scratch.txt"`))
	if _, err := os.Stat(filepath.Join(box.state.Temp, "scratch.txt")); err != nil {
		t.Errorf("TEMP was not redirected into the sandbox: %v", err)
	}
}
