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

	err := removeSandbox(s.Group)
	if got := exit.Of(err); got != exit.Failed {
		t.Fatalf("exit code is %v, want %v (error: %v)", got, exit.Failed, err)
	}
	if _, statErr := os.Stat(state.Path(s.Group)); statErr != nil {
		t.Errorf("the record was deleted although the removal did not finish: %v", statErr)
	}

	// Once the obstacle is gone, running it again has to finish the job.
	release()
	if err := removeSandbox(s.Group); err != nil {
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
	if err := removeSandbox("wub-never-created"); err != nil {
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

	if err := removeSandbox(s.Group); err != nil {
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
