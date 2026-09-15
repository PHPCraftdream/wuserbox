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
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
)

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
