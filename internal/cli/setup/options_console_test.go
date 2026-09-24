package setup

import (
	"os"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
)

func TestRunSelectsConsoleFromCallerStreams(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		terminal   bool
		wantOwn    bool
		wantRelay  bool
		wantDetect bool
	}{
		{name: "interactive default", terminal: true, wantRelay: true, wantDetect: true},
		{name: "redirected default", wantDetect: true},
		{name: "plain override", args: []string{"--plain-stdio"}, terminal: true},
		{name: "relay override", args: []string{"--console-relay"}, wantRelay: true},
		{name: "own console override", args: []string{"--own-console"}, terminal: true, wantOwn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(proc.EnvOwnConsole, "stale")
			t.Setenv(proc.EnvConsoleRelay, "stale")
			calls := 0
			args := append(append([]string(nil), tc.args...), "--", "cmd")
			_, command, err := parseOptions("run", args, func() bool {
				calls++
				return tc.terminal
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(command) != 1 || command[0] != "cmd" {
				t.Errorf("command changed: %v", command)
			}
			if (os.Getenv(proc.EnvOwnConsole) != "") != tc.wantOwn ||
				(os.Getenv(proc.EnvConsoleRelay) != "") != tc.wantRelay {
				t.Errorf("console mode: own=%q relay=%q", os.Getenv(proc.EnvOwnConsole), os.Getenv(proc.EnvConsoleRelay))
			}
			if (calls != 0) != tc.wantDetect {
				t.Errorf("terminal detection called %d times", calls)
			}
		})
	}
}

func TestConsoleOverridesRefuseConflicts(t *testing.T) {
	for _, args := range [][]string{
		{"--plain-stdio", "--console-relay"},
		{"--plain-stdio", "--own-console"},
		{"--console-relay", "--own-console"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			t.Setenv(proc.EnvOwnConsole, "")
			t.Setenv(proc.EnvConsoleRelay, "")
			_, _, err := parseOptions("run", args, func() bool {
				t.Fatal("invalid flags must fail before terminal detection")
				return false
			})
			if err == nil {
				t.Fatal("conflicting console flags were accepted")
			}
			for _, arg := range args {
				if !strings.Contains(err.Error(), arg) {
					t.Errorf("error does not name %s: %v", arg, err)
				}
			}
			if os.Getenv(proc.EnvOwnConsole) != "" || os.Getenv(proc.EnvConsoleRelay) != "" {
				t.Error("invalid flags changed the console mode")
			}
		})
	}
}

func TestInitDoesNotSelectAConsole(t *testing.T) {
	t.Setenv(proc.EnvOwnConsole, "")
	t.Setenv(proc.EnvConsoleRelay, "")
	_, _, err := parseOptions("init", nil, func() bool {
		t.Fatal("init must not inspect the caller terminal")
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv(proc.EnvOwnConsole) != "" || os.Getenv(proc.EnvConsoleRelay) != "" {
		t.Fatal("init selected a run console")
	}
	if _, _, err := parseOptions("init", []string{"--plain-stdio"}, func() bool { return true }); err == nil {
		t.Fatal("init accepted a run-only option")
	}
}

func TestAllConsoleStreamsRejectsPipesAndMissingHandles(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if allConsoleStreams(read, write, os.Stderr) || allConsoleStreams(nil, os.Stdout, os.Stderr) {
		t.Fatal("a pipe or missing handle was mistaken for a terminal")
	}
}
