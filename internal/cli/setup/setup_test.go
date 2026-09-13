package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseOptionsDefaultsToTheCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	restore, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(restore) })

	options, command, err := ParseOptions("run", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(filepath.Clean(options.Dir), filepath.Clean(dir)) {
		t.Errorf("project directory is %q, want %q", options.Dir, dir)
	}
	if len(command) != 0 {
		t.Errorf("unexpected command %v", command)
	}
}

func TestParseOptionsSeparatesTheCommand(t *testing.T) {
	options, command, err := ParseOptions("run",
		[]string{"--dir", `C:\project`, "--rw", `C:\tools`, "--rw", `C:\logs`, "--ro", `C:\docs`, "--", "git", "status", "--short"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Dir != `C:\project` {
		t.Errorf("project directory is %q", options.Dir)
	}
	if len(options.RW) != 2 || options.RW[1] != `C:\logs` {
		t.Errorf("writable directories are %v", options.RW)
	}
	if len(options.RO) != 1 {
		t.Errorf("readable directories are %v", options.RO)
	}
	want := []string{"git", "status", "--short"}
	if len(command) != len(want) {
		t.Fatalf("command is %v, want %v", command, want)
	}
	for i := range want {
		if command[i] != want[i] {
			t.Fatalf("command is %v, want %v", command, want)
		}
	}
}

func TestParseOptionsReadsTheSwitches(t *testing.T) {
	options, _, err := ParseOptions("init", []string{"--dir", `C:\p`, "--no-ai", "--home-writes"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.NoAI || !options.HomeWrites {
		t.Errorf("switches were not read: %+v", options)
	}
}

func TestParseOptionsRejectsUnknownFlags(t *testing.T) {
	if _, _, err := ParseOptions("run", []string{"--nonsense"}); err == nil {
		t.Error("expected an error")
	}
}

func TestOptionsSurviveARoundTripThroughArguments(t *testing.T) {
	original, _, err := ParseOptions("init",
		[]string{"--dir", `C:\project`, "--rw", `C:\tools`, "--ro", `C:\docs`, "--no-ai", "--home-writes"})
	if err != nil {
		t.Fatal(err)
	}
	args := original.Args()
	if args[0] != "init" {
		t.Fatalf("rebuilt arguments start with %q", args[0])
	}
	rebuilt, _, err := ParseOptions("init", args[1:])
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Dir != original.Dir || rebuilt.NoAI != original.NoAI ||
		rebuilt.HomeWrites != original.HomeWrites ||
		len(rebuilt.RW) != len(original.RW) || len(rebuilt.RO) != len(original.RO) {
		t.Errorf("options changed across the round trip: %+v then %+v", original, rebuilt)
	}
}
