// Tests for the command line: what the options mean, what running takes and
// what configuring takes, where the program to run begins, and the agreement
// between the flags a command registers and the flags its help documents.

package setup

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
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
	// The dash matters here too: a re-exec through Elevate reads a bare word
	// as a program to run, not as init.
	if args[0] != "--init" {
		t.Fatalf("rebuilt arguments start with %q, want \"--init\"", args[0])
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

func TestParseOptionsReadsQuietAndNonInteractive(t *testing.T) {
	os.Unsetenv(EnvNonInteractive)
	options, _, err := ParseOptions("run", []string{"--dir", `C:\p`, "--quiet", "--non-interactive", "--", "cmd"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.Quiet {
		t.Error("--quiet was not read")
	}
	if os.Getenv(EnvNonInteractive) == "" {
		t.Error("--non-interactive did not reach the environment")
	}
	os.Unsetenv(EnvNonInteractive)
}

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

// TestRunRefusesToConfigureWhileItRuns covers the line drawn between starting
// a program and deciding what it may write. A directory handed over by a flag
// on one run and forgotten on the next is a sandbox nobody can reason about,
// so those flags belong to init and to the rules file instead.
func TestRunRefusesToConfigureWhileItRuns(t *testing.T) {
	for _, args := range [][]string{
		{"--rw", `C:\tools`, "cmd.exe"},
		{"--ro", `C:\tools`, "cmd.exe"},
		{"--no-ai", "cmd.exe"},
		{"--home-writes", "cmd.exe"},
	} {
		err := Run(args)
		if got := exit.Of(err); got != exit.Usage {
			t.Errorf("%v: exit code is %v, want %v (error: %v)", args, got, exit.Usage, err)
			continue
		}
		if !strings.Contains(err.Error(), "wuserbox --") {
			t.Errorf("%v: the message does not name a runnable command to use instead: %v", args, err)
		}
	}
}

// TestRunStillTakesTheOptionsAboutRunning keeps the flags that describe this
// one run rather than the sandbox.
func TestRunStillTakesTheOptionsAboutRunning(t *testing.T) {
	options, command, err := ParseOptions("run", []string{
		"--dir", t.TempDir(), "--quiet", "--json", "--dry-run", "cmd.exe", "/c", "echo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.Quiet || !options.JSON || !options.DryRun {
		t.Errorf("the options came back as %+v", options)
	}
	if len(command) != 3 || command[0] != "cmd.exe" {
		t.Errorf("the command came back as %v", command)
	}
	if err := onlyRunning(options); err != nil {
		t.Errorf("a plain run was refused: %v", err)
	}
}

// TestAProgramNeedsNoSeparator is the shape the command now has: options
// first, program next, and everything after it belongs to the program.
func TestAProgramNeedsNoSeparator(t *testing.T) {
	_, command, err := ParseOptions("run", []string{"cmd.exe", "/c", "echo", "--dir", "x"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cmd.exe", "/c", "echo", "--dir", "x"}
	if len(command) != len(want) {
		t.Fatalf("the command came back as %v", command)
	}
	for i := range want {
		if command[i] != want[i] {
			t.Errorf("argument %d is %q, want %q", i, command[i], want[i])
		}
	}
}

// TestASeparatorInsideTheProgramsOwnArgumentsSurvives is the regression guard
// for a "--" that never belonged to wuserbox at all. A single scan for the
// first "--" anywhere in the arguments used to strip it wherever it turned
// up, so `wuserbox git checkout -- file.txt` silently became
// `git checkout file.txt`, changing what git was told. wuserbox's own "--"
// only ever appears before the program name, so parsing must stop there and
// leave everything after the program alone, "--" included.
func TestASeparatorInsideTheProgramsOwnArgumentsSurvives(t *testing.T) {
	_, command, err := ParseOptions("run", []string{"git", "checkout", "--", "file.txt"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"git", "checkout", "--", "file.txt"}
	if len(command) != len(want) {
		t.Fatalf("command is %v, want %v", command, want)
	}
	for i := range want {
		if command[i] != want[i] {
			t.Fatalf("command is %v, want %v", command, want)
		}
	}
}

// TestTheExplicitRunSeparatorStillWorks keeps the one spelling that leans on
// wuserbox's own "--": nothing before it, so flag.Parse reads it as the end of
// wuserbox's own flags rather than as something belonging to the program.
func TestTheExplicitRunSeparatorStillWorks(t *testing.T) {
	_, command, err := ParseOptions("run", []string{"--", "list"})
	if err != nil {
		t.Fatal(err)
	}
	if len(command) != 1 || command[0] != "list" {
		t.Errorf("command is %v, want [list]", command)
	}
}

// TestAMistypedCommandSaysSo keeps a typo from being reported as a missing
// program, now that anything which is not a command is taken for one.
func TestAMistypedCommandSaysSo(t *testing.T) {
	err := Run([]string{"frobnicate"})
	if got := exit.Of(err); got != exit.Usage {
		t.Fatalf("exit code is %v, want %v (error: %v)", got, exit.Usage, err)
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("unhelpful message: %v", err)
	}
	// Something that looks like a path is reported as what it is.
	pathLike := Run([]string{`C:\no\such\program.exe`})
	if pathLike == nil || strings.Contains(pathLike.Error(), "unknown command") {
		t.Errorf("a path was reported as a command: %v", pathLike)
	}
}

// TestTheHelpListsExactlyTheFlagsSetupTakes holds init, run and rm to their
// entries. The options in the help are written by hand; without this, a command
// can gain a flag the manual never mentions or keep one it no longer reads.
func TestTheHelpListsExactlyTheFlagsSetupTakes(t *testing.T) {
	initFlags, _ := sharedFlags("init")
	checkAgainstHelp(t, "init", initFlags, nil)
	rm, _ := rmFlags()
	checkAgainstHelp(t, "rm", rm, nil)

	// A run shares init's flag set and turns four of them down by name, so that
	// asking for one is answered with where it belongs. Its entry does not list
	// them, because they are not options of running — and the exception is read
	// from the list that defines it rather than written out again here, so a
	// fifth one cannot be added without this seeing it.
	refused := map[string]bool{}
	for _, configuring := range configuringFlags {
		refused[configuring.flag] = true
	}
	run, _ := sharedFlags("run")
	checkAgainstHelp(t, "run", run, refused)
}

func checkAgainstHelp(t *testing.T, command string, flags *flag.FlagSet, refused map[string]bool) {
	t.Helper()
	undocumented, missing := usage.Mismatch(command, flags)
	for _, name := range undocumented {
		if refused[name] {
			continue
		}
		t.Errorf("%s takes --%s, which its help never mentions", command, name)
	}
	if len(missing) > 0 {
		t.Errorf("the help offers %v on %s, which it would reject", missing, command)
	}
}

// TestARefusedFlagIsRefusedBySomethingTheHelpAgreesWith keeps the exception
// above from becoming a hiding place: a flag a run turns down has to actually
// be turned down, with the message that says where it belongs.
func TestARefusedFlagIsRefusedBySomethingTheHelpAgreesWith(t *testing.T) {
	for _, configuring := range configuringFlags {
		options := sandbox.Options{}
		switch configuring.flag {
		case "rw":
			options.RW = []string{`C:\tools`}
		case "ro":
			options.RO = []string{`C:\tools`}
		case "no-ai":
			options.NoAI = true
		case "home-writes":
			options.HomeWrites = true
		default:
			t.Fatalf("--%s is refused by a run, and this test does not know how to set it", configuring.flag)
		}
		err := onlyRunning(options)
		if err == nil {
			t.Errorf("--%s was accepted by a run", configuring.flag)
			continue
		}
		if !strings.Contains(err.Error(), configuring.instead) {
			t.Errorf("--%s is refused without saying to use %q: %v",
				configuring.flag, configuring.instead, err)
		}
	}
}
