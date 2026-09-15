// Tests for building a sandbox: which preset it is offered, what an existing
// one already holds, the decision it made once and keeps, and asking for
// administrator rights where prompts are switched off.

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/facts"
)

// TestMain loads the ktav parser before any test moves LOCALAPPDATA. The
// parser caches a native library under that directory and keeps it open for
// the life of this binary, which would otherwise leave whichever test's
// temporary directory it landed in undeletable -- the same fix
// internal/sandbox/grants carries, for the same reason.
func TestMain(m *testing.M) {
	warm, err := os.CreateTemp("", "wuserbox-warm-*.ktav")
	if err == nil {
		_, _ = warm.WriteString("projects: [\n]\n")
		warm.Close()
		os.Setenv(config.EnvPath, warm.Name())
		_, _ = config.Load() // reaches the parser, which loads its library once
		os.Remove(warm.Name())
		os.Unsetenv(config.EnvPath)
	}
	os.Exit(m.Run())
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

// TestReconcilePresetHonoursTheSandboxsOwnDecision is the regression guard
// for a legacy grant on a real agent directory -- the kind a sandbox built
// before profile copying existed still carries -- surviving past the flag
// that should take it back. Nothing hands the real directory out any more:
// a sandbox's own profile is filled by copying, not by granting it.
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
	}
	if err := s.Add(agent, grant.RW); err != nil {
		t.Fatal(err) // the legacy grant this test is about
	}

	// A plain run with the preset wanted retires it: nothing hands real
	// agent directories out any more, so a sandbox from before that changed
	// must not go on holding one.
	plainRun := sandbox.Options{Dir: s.Dir}
	if err := reconcilePreset(s, plainRun); err != nil {
		t.Fatal(err)
	}
	if s.Has(agent) {
		t.Error("a plain run left a legacy agent-directory grant standing")
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

// What has to be built again is not always the same event, and saying
// "creating sandbox" for one that has existed for months -- and keeps every
// permission it was ever given -- tells the reader the wrong thing about
// what is happening to it.
func TestWhatHasToBeBuiltAgainIsNamedForWhatItActuallyIs(t *testing.T) {
	const name = "wub-nothing-by-this-name-00000000"

	if said := missing(name, nil); !strings.Contains(said, "creating sandbox") {
		t.Errorf("a sandbox that was never recorded was announced as %q", said)
	}
	// A record naming a group this machine does not know. That is a sandbox
	// whose group went away, not a sandbox being made for the first time.
	said := missing(name, &state.State{Group: name, Dir: t.TempDir(), Secret: "sealed"})
	if !strings.Contains(said, string(facts.GroupGone)) {
		t.Errorf("a sandbox whose group is gone was announced as %q", said)
	}
	if strings.Contains(said, "creating sandbox") {
		t.Errorf("a sandbox that already existed was announced as new: %q", said)
	}
}

// The run path must not fall back to the old mechanism without a word. It
// starts ordinary programs, so the sandbox looks fine right up until a shell
// fails to start, for reasons pointing nowhere near the missing account.
func TestARunRefusesASandboxWithNoAccountAndSaysWhatFixesIt(t *testing.T) {
	s := &state.State{Group: "wub-old-00000000", Dir: t.TempDir()}
	if s.Account != "" {
		t.Fatal("this test is about a record with no account")
	}
	err := refuseWithoutAccount(s)
	if err == nil {
		t.Fatal("a sandbox with no account of its own was allowed to run")
	}
	for _, want := range []string{"--init", s.Dir, s.Group} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// The run path and the listing must call the same state the same thing. Two
// vocabularies for one state would leave somebody reading "--list --long"
// unable to tell it was describing what the last run complained about.
func TestTheRunPathCallsAStateWhatTheListingCallsIt(t *testing.T) {
	const name = "wub-nothing-by-this-name-00000000"
	said := missing(name, &state.State{Group: name, Dir: t.TempDir(), Secret: "sealed"})
	if !strings.Contains(said, string(facts.GroupGone)) {
		t.Errorf("the run path says %q, where the listing would say %q", said, facts.GroupGone)
	}
}

// TestRunFillsTheProfileFromTheRulesFile is the regression guard for the
// wiring itself: policy/profile.Copy existed, was tested on its own, and
// nothing in a run ever called it. A sandbox's own profile stayed empty of
// anything the rules file named, no matter what that file said.
func TestRunFillsTheProfileFromTheRulesFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if err := os.WriteFile(filepath.Join(home, "credentials.json"), []byte(`{"token":"abc"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	if err := (&config.Config{Profile: []string{"credentials.json"}}).Save(); err != nil {
		t.Fatal(err)
	}

	profileDir := t.TempDir()
	s := &state.State{Group: "wub-fill-test-00000000", Profile: profileDir}
	if err := fillProfile(s); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(profileDir, "credentials.json"))
	if err != nil {
		t.Fatalf("the rules file named credentials.json and it was not copied in: %v", err)
	}
	if string(got) != `{"token":"abc"}` {
		t.Errorf("copied %q, want the source's own content", got)
	}

	// And it is remembered for next time, in the bookkeeping fillProfile owns
	// -- not in the profile itself, which the sandbox may write.
	recorded, err := facts.Copied(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 || recorded[0] != "credentials.json" {
		t.Errorf("what was copied was not recorded: %v", recorded)
	}
}

// TestRunClearsTheProfileWhenTheAgentPresetIsWithheld is the regression
// guard for --no-ai meaning nothing at the profile-copy layer: the rules
// file's `profile:` section is pre-filled with exactly the agent state
// directories --no-ai exists to withhold, so consulting that section for
// this flag would make it withhold nothing on every ordinary rules file.
func TestRunClearsTheProfileWhenTheAgentPresetIsWithheld(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if err := os.WriteFile(filepath.Join(home, "credentials.json"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	if err := (&config.Config{Profile: []string{"credentials.json"}}).Save(); err != nil {
		t.Fatal(err)
	}

	profileDir := t.TempDir()
	s := &state.State{Group: "wub-clear-test-00000000", Profile: profileDir}
	if err := fillProfile(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(profileDir, "credentials.json")); err != nil {
		t.Fatalf("nothing was copied in the first place, so this test proves nothing: %v", err)
	}

	s.NoAI = true
	if err := fillProfile(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(profileDir, "credentials.json")); !os.IsNotExist(err) {
		t.Errorf("--no-ai left a copy of an agent credential in the profile: %v", err)
	}
	recorded, err := facts.Copied(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 0 {
		t.Errorf("the bookkeeping still lists %v after --no-ai cleared the profile", recorded)
	}
}
