package setup

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
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

// TestPreviewInputReflectsWhatAnExistingSandboxActuallyHolds is the
// regression guard for a --dry-run that showed a hypothetical sandbox rather
// than the real one. Preview used to build its plan from this invocation's
// own flags alone: a plain run's options.NoAI is always false, so a sandbox
// saved with --no-ai still showed the agent preset; and a directory handed
// over once with --grant lives only in the record, so it never appeared at
// all.
func TestPreviewInputReflectsWhatAnExistingSandboxActuallyHolds(t *testing.T) {
	grantedOnce := `C:\granted-once`
	existing := &state.State{
		Dir: `C:\project`, Temp: `C:\temp`, NoAI: true,
		Grants: []grant.Spec{{Path: grantedOnce, Kind: grant.RW}},
	}
	plainRun := sandbox.Options{Dir: existing.Dir}

	in := previewInput(plainRun, "wub-test", existing.Dir, existing)
	if !in.NoAI {
		t.Error("a saved --no-ai was not carried into the preview")
	}
	found := false
	for _, spec := range in.Existing {
		if spec.Path == grantedOnce {
			found = true
		}
	}
	if !found {
		t.Error("a directory granted once is missing from the preview's input")
	}

	// And a sandbox that does not exist yet still gets a sensible plan.
	fresh := previewInput(plainRun, "wub-test", existing.Dir, nil)
	if fresh.NoAI {
		t.Error("a sandbox with no record should not start out as --no-ai")
	}
	if len(fresh.Existing) != 0 {
		t.Error("a sandbox with no record has nothing existing to show")
	}
}

// TestRebuildOptionsCarriesForwardAPersistedNoAIDecision is the regression
// guard for the other place --no-ai can lapse. A run cannot carry the flag
// either, and when the sandbox has to be rebuilt from scratch — the group is
// missing, or broken — the elevated re-exec used to be built from the run's
// own options alone, which never set NoAI. That read as "presets are wanted
// again" and handed the agent directories back to a sandbox --no-ai had
// explicitly taken them from.
func TestRebuildOptionsCarriesForwardAPersistedNoAIDecision(t *testing.T) {
	plainRun := sandbox.Options{Dir: `C:\project`}
	existing := &state.State{NoAI: true}

	got := rebuildOptions(plainRun, existing)
	if !got.NoAI {
		t.Error("a persisted --no-ai decision was dropped when the sandbox had to be rebuilt")
	}
	args := got.Args()
	found := false
	for _, a := range args {
		if a == "--no-ai" {
			found = true
		}
	}
	if !found {
		t.Errorf("the rebuild command line does not carry --no-ai: %v", args)
	}
}

// TestRebuildOptionsLeavesANewSandboxAlone keeps a project that was never
// configured from being handed --no-ai it never asked for.
func TestRebuildOptionsLeavesANewSandboxAlone(t *testing.T) {
	plainRun := sandbox.Options{Dir: `C:\project`}
	if got := rebuildOptions(plainRun, nil); got.NoAI {
		t.Error("NoAI should stay false when nothing was ever recorded")
	}
	if got := rebuildOptions(plainRun, &state.State{NoAI: false}); got.NoAI {
		t.Error("NoAI should stay false when the record agrees with the run")
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

// TestClearGrantsReachesWhatANestedGrantPinned is the regression guard for the
// half of --rm that was never there.
//
// Deleting a sandbox revoked each path it held and stopped. Handing a
// directory over pins its permission list, copying what it was handed from
// above into its own entries, so a directory inside a granted one that another
// sandbox was given carries a copy of this sandbox's entry — and that copy no
// longer hears from the directory above it. Revoking the outer path left it
// standing, and --rm went on to delete the group and report success over
// permissions that were still in force with nothing left pointing at them.
func TestClearGrantsReachesWhatANestedGrantPinned(t *testing.T) {
	const (
		removed = "S-1-5-21-1111111111-2222222222-3333333333-515151"
		other   = "S-1-5-21-1111111111-2222222222-3333333333-525252"
	)
	outer := t.TempDir()
	inner := filepath.Join(outer, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := grant.Apply(removed, outer, grant.RW); err != nil {
		t.Fatal(err)
	}
	// Granting the inner one to somebody else is what pins it, with the entry
	// of the sandbox about to be deleted among the copies.
	if err := grant.Apply(other, inner, grant.RW); err != nil {
		t.Fatal(err)
	}
	writable, err := access.Check(removed, filepath.Join(inner, "f.txt"), access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !writable.Allowed {
		t.Fatal("the sandbox could not write inside the pinned directory, so this proves nothing")
	}

	s := &state.State{
		Group:  "wub-rm-test",
		SID:    removed,
		Dir:    outer,
		Temp:   t.TempDir(),
		Grants: []grant.Spec{{Path: outer, Kind: grant.RW}},
	}
	if left := clearGrants(s, true); len(left) > 0 {
		t.Fatalf("clearing the grants did not finish: %v", left)
	}

	after, err := access.Check(removed, filepath.Join(inner, "f.txt"), access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if after.Allowed {
		t.Error("a deleted sandbox still reaches inside what a nested grant pinned")
	}
	// The sandbox the inner directory belongs to is untouched by any of it.
	kept, err := access.Check(other, filepath.Join(inner, "f.txt"), access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !kept.Allowed {
		t.Errorf("removing one sandbox cost another its own grant: %s", kept.Reason)
	}
}
