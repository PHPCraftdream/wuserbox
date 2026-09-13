package e2e

import (
	"os"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/exec"
)

// runSandboxed executes args in the sandbox and returns the exit code.
func runSandboxed(t *testing.T, s *state.State, args []string) int {
	t.Helper()
	oldTemp, oldTmp := os.Getenv("TEMP"), os.Getenv("TMP")
	defer func() {
		os.Setenv("TEMP", oldTemp)
		os.Setenv("TMP", oldTmp)
	}()
	commandLine, err := exec.CommandLine(args)
	if err != nil {
		t.Fatalf("building the command line for %v: %v", args, err)
	}
	code, err := exec.Run(s, commandLine)
	if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return code
}

// mustSucceed runs a command that is expected to work inside the sandbox.
func mustSucceed(t *testing.T, s *state.State, args []string) {
	t.Helper()
	if code := runSandboxed(t, s, args); code != 0 {
		t.Errorf("expected %v to succeed, exit code %d", args, code)
	}
}

// mustFail runs a command that the sandbox must refuse.
func mustFail(t *testing.T, s *state.State, args []string) {
	t.Helper()
	if code := runSandboxed(t, s, args); code == 0 {
		t.Errorf("expected %v to be denied, but it succeeded", args)
	}
}
