package launch

import (
	"strings"
	"testing"
)

func TestRunNeedsACommand(t *testing.T) {
	err := Run([]string{"--dir", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "no command given") {
		t.Errorf("got %v", err)
	}
}

func TestRunReportsAMissingProgramBeforeTouchingTheSandbox(t *testing.T) {
	// The program is resolved first, so a typo fails without creating
	// anything or asking for administrator rights.
	err := Run([]string{"--dir", t.TempDir(), "--", "no-such-program-wuserbox"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "administrator") {
		t.Errorf("elevation was attempted before checking the command: %v", err)
	}
}

func TestRunRejectsUnknownOptions(t *testing.T) {
	if err := Run([]string{"--nonsense", "--", "cmd"}); err == nil {
		t.Error("expected an error")
	}
}
