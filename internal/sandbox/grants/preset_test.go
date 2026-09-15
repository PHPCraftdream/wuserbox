// Tests for the agent preset: handing it over, withholding it, taking it
// back, and leaving a directory somebody narrowed by hand narrow.

package grants

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
)

func TestDropPresetTakesBackTheAgentDirectories(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	agent := filepath.Join(home, ".claude")
	if err := os.Mkdir(agent, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newState(t)
	project := s.Dir

	if err := s.Add(project, grant.RW); err != nil {
		t.Fatal(err)
	}
	for _, spec := range preset.AI() {
		if err := s.Add(spec.Path, spec.Kind); err != nil {
			t.Fatal(err)
		}
	}
	if !s.Has(agent) {
		t.Fatal("the preset did not grant the agent directory")
	}

	if err := DropPreset(s); err != nil {
		t.Fatal(err)
	}
	if s.Has(agent) {
		t.Error("the agent directory survived --no-ai")
	}
	if !s.Has(project) {
		t.Error("the project directory was taken away as well")
	}
	stored, err := state.Load(s.Group)
	if err != nil || stored == nil {
		t.Fatalf("state was not persisted: %v", err)
	}
	if stored.Has(agent) {
		t.Error("the persisted state still lists the agent directory")
	}
}

func TestDropPresetIsHarmlessWhenNothingWasGranted(t *testing.T) {
	t.Setenv("USERPROFILE", tempDir(t))
	s := newState(t)
	if err := DropPreset(s); err != nil {
		t.Fatal(err)
	}
}

// TestDropPresetIsWhatWithholdingMeans is the regression guard for a sandbox
// that kept its agent directories when the flag said to withhold them:
// skipping the preset is not the same as taking it back.
func TestDropPresetIsWhatWithholdingMeans(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	agent := filepath.Join(home, ".claude")
	if err := os.Mkdir(agent, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newState(t)
	for _, spec := range preset.AI() {
		if err := s.Add(spec.Path, spec.Kind); err != nil {
			t.Fatal(err)
		}
	}
	if !s.Has(agent) {
		t.Fatal("the preset did not grant the agent directory")
	}
	// Applying the preset with it switched off has to leave nothing behind.
	if err := DropPreset(s); err != nil {
		t.Fatal(err)
	}
	if s.Has(agent) {
		t.Error("the agent directory survived; a later run would still reach it")
	}
}

// TestDropPresetKeepsTheProjectItself covers a sandbox whose project sits in
// one of the agent directories: withholding the preset must not take away the
// one permission the sandbox exists for.
func TestDropPresetKeepsTheProjectItself(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	project := filepath.Join(home, ".claude")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCALAPPDATA", tempDir(t))
	s := &state.State{
		Group: "wub-inside-preset",
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-151515",
		Dir:   project,
		Temp:  tempDir(t),
	}
	if err := s.Add(project, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := DropPreset(s); err != nil {
		t.Fatal(err)
	}
	if !s.Has(project) {
		t.Error("--no-ai took away the project directory itself")
	}
}

// TestApplyPresetBringsASandboxInLineWithTheFlags is the regression guard for
// flags that only counted on the run that built the sandbox. A plain run after
// one with --no-ai left the agent directories withheld, and --home-writes did
// nothing at all for a sandbox created without it.
func TestApplyPresetBringsASandboxInLineWithTheFlags(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))
	agent := filepath.Join(home, ".claude")
	if err := os.Mkdir(agent, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newState(t)

	// A run with the preset withheld leaves nothing behind.
	if err := DropPreset(s); err != nil {
		t.Fatal(err)
	}
	if s.Has(agent) {
		t.Fatal("the agent directory was not withheld")
	}

	// The next plain run puts it back.
	if err := ApplyPreset(s, false); err != nil {
		t.Fatal(err)
	}
	if !s.Has(agent) {
		t.Error("a plain run did not restore the agent directories")
	}
	if s.Has(home) {
		t.Error("the profile root was handed over without being asked for")
	}

	// And asking for the profile root reaches a sandbox built without it.
	if err := ApplyPreset(s, true); err != nil {
		t.Fatal(err)
	}
	if !s.Has(home) {
		t.Error("--home-writes did not reach an existing sandbox")
	}
}

// TestApplyPresetLeavesANarrowedDirectoryNarrow is the regression guard for a
// preset that ran on every start and applied its own idea of the access. A
// directory narrowed by hand with `grant ~/.claude --ro` was writable again
// after the next plain run, and nothing said so.
func TestApplyPresetLeavesANarrowedDirectoryNarrow(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))
	agent := filepath.Join(home, ".claude")
	if err := os.Mkdir(agent, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newState(t)
	if err := ApplyPreset(s, false); err != nil {
		t.Fatal(err)
	}
	if kind, _ := s.Kind(agent); kind != grant.RW {
		t.Fatalf("the preset handed the agent directory over as %q", kind)
	}

	// The user narrows it by hand, the way `grant <dir> --ro` does.
	if err := s.Add(agent, grant.RO); err != nil {
		t.Fatal(err)
	}
	refused, err := access.Check(testAccount, agent, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if refused.Allowed {
		t.Fatalf("narrowing the directory did not refuse creation: %s", refused.Reason)
	}

	// Every later run applies the preset again, and must leave that alone.
	for i := 0; i < 2; i++ {
		if err := ApplyPreset(s, false); err != nil {
			t.Fatal(err)
		}
	}
	if kind, _ := s.Kind(agent); kind != grant.RO {
		t.Errorf("the preset widened the directory back to %q", kind)
	}
	answer, err := access.Check(testAccount, agent, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the sandbox can create files in a directory the user narrowed: %s", answer.Reason)
	}
}

// TestApplyPresetStillReachesADirectoryNobodyAskedAbout keeps the preset
// working where no one has said anything: an agent directory that appears
// after the sandbox was built is still handed over.
func TestApplyPresetStillReachesADirectoryNobodyAskedAbout(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))
	s := newState(t)
	if err := ApplyPreset(s, false); err != nil {
		t.Fatal(err)
	}
	agent := filepath.Join(home, ".codex")
	if err := os.Mkdir(agent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ApplyPreset(s, false); err != nil {
		t.Fatal(err)
	}
	if kind, found := s.Kind(agent); !found || kind != grant.RW {
		t.Errorf("a new agent directory was not handed over: kind %q, found %v", kind, found)
	}
}

// TestEnsurePutsBackAPermissionThatWasRemoved is the regression guard for the
// advice explain gives: running init again has to repair a sandbox, and it
// could not, because a recorded permission was taken as proof that the
// permission existed.
func TestEnsurePutsBackAPermissionThatWasRemoved(t *testing.T) {
	s := newState(t)
	target := tempDir(t)
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	allowed, err := access.Check(s.SID, target, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Allowed {
		t.Fatal("the sandbox was not given the directory in the first place")
	}

	// Someone removes the entry by hand; the record still claims it is there.
	if err := grant.Revoke(s.SID, target); err != nil {
		t.Fatal(err)
	}
	if gone, err := access.Check(s.SID, target, access.Create); err != nil {
		t.Fatal(err)
	} else if gone.Allowed {
		t.Fatal("the permission survived being revoked")
	}
	if !s.Has(target) {
		t.Fatal("the record forgot the directory, which is not the case under test")
	}

	// The fast path trusts the record and changes nothing.
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if still, err := access.Check(s.SID, target, access.Create); err != nil {
		t.Fatal(err)
	} else if still.Allowed {
		t.Fatal("the fast path applied the permission; the test no longer covers the repair")
	}

	// Repair acts on the file system instead.
	if err := s.Ensure(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	back, err := access.Check(s.SID, target, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Allowed {
		t.Errorf("init would not have repaired the sandbox: %s", back.Reason)
	}
}

// TestReapplyReachesADirectoryGivenByHand is the regression guard for a repair
// that only covered what it could recompute. A directory handed over once with
// grant or --rw lives in the record and nowhere else, so init walked straight
// past it and the advice to run init again did nothing for it.
func TestReapplyReachesADirectoryGivenByHand(t *testing.T) {
	s := newState(t)
	byHand := tempDir(t)
	if err := s.Add(byHand, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := grant.Revoke(s.SID, byHand); err != nil {
		t.Fatal(err)
	}
	if gone, err := access.Check(s.SID, byHand, access.Create); err != nil {
		t.Fatal(err)
	} else if gone.Allowed {
		t.Fatal("the permission survived being revoked")
	}

	if err := Reapply(s); err != nil {
		t.Fatal(err)
	}
	back, err := access.Check(s.SID, byHand, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Allowed {
		t.Errorf("repair missed a directory that was given by hand: %s", back.Reason)
	}
}

func TestReapplySkipsWhatIsNoLongerThere(t *testing.T) {
	s := newState(t)
	gone := tempDir(t)
	if err := s.Add(gone, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}
	if err := Reapply(s); err != nil {
		t.Errorf("a directory that was removed should not fail the repair: %v", err)
	}
}
