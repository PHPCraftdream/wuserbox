package setup

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
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

func TestElevateRefusesWhenPromptsAreOff(t *testing.T) {
	t.Setenv(EnvNonInteractive, "1")
	err := Elevate([]string{"init", "--dir", t.TempDir()})
	if err == nil {
		t.Fatal("elevation should have been refused")
	}
	if got := exit.Of(err); got != exit.NeedsElevation {
		t.Errorf("exit code is %v, want %v", got, exit.NeedsElevation)
	}
	if !strings.Contains(err.Error(), "administrator rights") {
		t.Errorf("unhelpful message: %v", err)
	}
}

// TestRemoveSandboxKeepsTheRecordWhenSomethingIsLeftBehind is the regression
// guard for a removal that printed its failures and reported success. A temp
// directory held open by another program stayed on disk while the record and
// the group that named it were deleted, so nothing was left to finish the job
// with and the command still exited 0.
func TestRemoveSandboxKeepsTheRecordWhenSomethingIsLeftBehind(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	temp := t.TempDir()
	s := &state.State{
		Group: "wub-rm-test",
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-202020",
		Dir:   t.TempDir(),
		Temp:  temp,
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	release := holdOpen(t, filepath.Join(temp, "busy.log"))
	defer release()

	err := removeSandbox(s.Group, false)
	if got := exit.Of(err); got != exit.Failed {
		t.Fatalf("exit code is %v, want %v (error: %v)", got, exit.Failed, err)
	}
	if _, statErr := os.Stat(state.Path(s.Group)); statErr != nil {
		t.Errorf("the record was deleted although the removal did not finish: %v", statErr)
	}

	// Once the obstacle is gone, running it again has to finish the job.
	release()
	if err := removeSandbox(s.Group, false); err != nil {
		t.Fatalf("the second attempt did not finish: %v", err)
	}
	if _, statErr := os.Stat(state.Path(s.Group)); !os.IsNotExist(statErr) {
		t.Errorf("the record survived a successful removal: %v", statErr)
	}
	if _, statErr := os.Stat(temp); !os.IsNotExist(statErr) {
		t.Error("the temp directory survived a successful removal")
	}
}

// TestRemoveSandboxSaysNothingAboutASandboxThatWasNeverThere keeps removal
// harmless where there is nothing to remove.
func TestRemoveSandboxSaysNothingAboutASandboxThatWasNeverThere(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if err := removeSandbox("wub-never-created", false); err != nil {
		t.Errorf("removing a sandbox that does not exist failed: %v", err)
	}
}

// holdOpen keeps a file open without letting anyone delete it, the way an
// editor or a running program does, and returns the release. Releasing twice
// is harmless.
func holdOpen(t *testing.T, path string) func() {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ,
		nil, syscall.CREATE_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		_ = syscall.CloseHandle(handle)
	}
}

// TestRemoveSandboxFinishesWhenAGrantedDirectoryIsGone is the regression guard
// for a removal that could never complete. A directory in the record that had
// since been deleted was counted as a permission that would not go, so every
// attempt failed on the same missing path and the sandbox stayed on the
// machine for good.
func TestRemoveSandboxFinishesWhenAGrantedDirectoryIsGone(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	gone := filepath.Join(t.TempDir(), "was-here")
	if err := os.Mkdir(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &state.State{
		Group: "wub-rm-missing",
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-212121",
		Dir:   t.TempDir(),
		Temp:  t.TempDir(),
	}
	if err := s.Add(gone, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}

	if err := removeSandbox(s.Group, false); err != nil {
		t.Fatalf("removal did not finish over a directory that no longer exists: %v", err)
	}
	if _, err := os.Stat(state.Path(s.Group)); !os.IsNotExist(err) {
		t.Errorf("the record survived a successful removal: %v", err)
	}
}

// TestRmRefusesADirectoryGivenAsAnArgument is the regression guard for a
// command given a directory as an argument: it ignored the path and removed
// the sandbox of the current directory instead.
func TestRmRefusesADirectoryGivenAsAnArgument(t *testing.T) {
	err := Rm([]string{t.TempDir(), "--dry-run"})
	if got := exit.Of(err); got != exit.Usage {
		t.Fatalf("exit code is %v, want %v (error: %v)", got, exit.Usage, err)
	}
	if !strings.Contains(err.Error(), "--dir") {
		t.Errorf("the message does not say how to name a project: %v", err)
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
		if !strings.Contains(err.Error(), "wuserbox ") {
			t.Errorf("%v: the message does not name a command to use instead: %v", args, err)
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

// TestReconcilePresetHonoursTheSandboxsOwnDecision is the regression guard
// for a decision that lapsed the moment nobody repeated it. A run never
// carries --no-ai — configuring is not something a run does — so reading
// options.NoAI to decide whether to reapply the preset meant a plain run
// right after `init --no-ai` silently handed the agent directories back.
func TestReconcilePresetHonoursTheSandboxsOwnDecision(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	agent := filepath.Join(home, ".claude")
	if err := os.Mkdir(agent, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &state.State{
		Group: "wub-reconcile-test",
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-303030",
		Dir:   t.TempDir(),
		Temp:  t.TempDir(),
		NoAI:  true, // what `init --no-ai` leaves behind
	}

	// A plain run's options never carry the flag; nothing here does.
	plainRun := sandbox.Options{Dir: s.Dir}
	if err := reconcilePreset(s, plainRun); err != nil {
		t.Fatal(err)
	}
	if s.Has(agent) {
		t.Error("a plain run handed the agent directory back, although --no-ai was never repeated")
	}

	// An explicit init without --no-ai is what is supposed to change the
	// sandbox's mind, and it does so by clearing the field before this runs.
	s.NoAI = false
	if err := reconcilePreset(s, plainRun); err != nil {
		t.Fatal(err)
	}
	if !s.Has(agent) {
		t.Error("clearing the decision did not bring the agent directory back")
	}
}
