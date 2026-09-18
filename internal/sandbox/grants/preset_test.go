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

// TestRetireAIGrantsTakesBackTheAgentDirectories is the regression guard for
// a sandbox built before a profile of its own existed: it may still hold a
// direct grant on the real agent directories, and RetireAIGrants -- called
// from ApplyPreset on every start, migration rather than a flag -- is what
// takes it back. ApplyPreset itself never grants these any more; a sandbox's
// own profile supplies that state now, filled by policy/profile.Copy.
func TestRetireAIGrantsTakesBackTheAgentDirectories(t *testing.T) {
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
		t.Fatal("the legacy grant this test is about was not applied")
	}

	if err := RetireAIGrants(s); err != nil {
		t.Fatal(err)
	}
	if s.Has(agent) {
		t.Error("the legacy agent directory grant survived")
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

// TestRetireAIGrantsKeepsTheProjectItself covers a sandbox whose project sits
// exactly at one of the agent directories: retiring a legacy grant must not
// take away the one permission the sandbox exists for.
func TestRetireAIGrantsKeepsTheProjectItself(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	project := filepath.Join(home, ".claude")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &state.State{
		Group: "wub-inside-preset",
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-151515",
		Dir:   project,
		Temp:  tempDir(t),
	}
	if err := s.Add(project, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := RetireAIGrants(s); err != nil {
		t.Fatal(err)
	}
	if !s.Has(project) {
		t.Error("retiring the legacy grant took away the project directory itself")
	}
}

func TestDropPresetIsHarmlessWhenNothingWasGranted(t *testing.T) {
	t.Setenv("USERPROFILE", tempDir(t))
	s := newState(t)
	if err := DropPreset(s); err != nil {
		t.Fatal(err)
	}
}

// TestDropPresetOnlyTakesBackTheProfileRoot is the regression guard for the
// split this file's other tests document: DropPreset answers --no-ai, and
// --no-ai is about the profile root only now, not the agent directories.
// Those are never granted by ApplyPreset any more, so there is nothing left
// for --no-ai to take back there; a legacy grant reached through some other
// route is RetireAIGrants's concern, not this one's, and DropPreset must
// leave it alone.
func TestDropPresetOnlyTakesBackTheProfileRoot(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	agent := filepath.Join(home, ".claude")
	if err := os.Mkdir(agent, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newState(t)
	if err := s.Add(home, grant.HomeTop); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(agent, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := DropPreset(s); err != nil {
		t.Fatal(err)
	}
	if s.Has(home) {
		t.Error("the profile root survived --no-ai")
	}
	if !s.Has(agent) {
		t.Error("DropPreset reached past the profile root, which is not its job any more")
	}
}

// TestDropPresetKeepsTheProjectItself covers a sandbox whose project
// directory is the profile root itself: taking the preset's profile-root
// grant back must not take away the one permission the sandbox exists for.
func TestDropPresetKeepsTheProjectItself(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	s := &state.State{
		Group: "wub-is-the-profile-root",
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-161616",
		Dir:   home,
		Temp:  tempDir(t),
	}
	if err := s.Add(home, grant.HomeTop); err != nil {
		t.Fatal(err)
	}
	if err := DropPreset(s); err != nil {
		t.Fatal(err)
	}
	if !s.Has(home) {
		t.Error("--no-ai took away the project directory itself")
	}
}

// TestApplyPresetBringsASandboxInLineWithTheFlags is the regression guard
// for --home-writes only counting on the run that built the sandbox, and for
// a legacy grant on a real agent directory surviving past the version that
// stopped handing those out -- ApplyPreset must retire it on the very next
// plain run, not only at init.
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
	if err := s.Add(agent, grant.RW); err != nil {
		t.Fatal(err)
	}

	if err := ApplyPreset(s, false); err != nil {
		t.Fatal(err)
	}
	if s.Has(agent) {
		t.Error("a plain run left a legacy agent-directory grant standing")
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
	allowed, err := access.Check(access.Sandbox{Group: s.SID}, target, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Allowed {
		t.Fatal("the sandbox was not given the directory in the first place")
	}

	// Someone removes the entry by hand; the record still claims it is there.
	if err := grant.Revoke(s.SID, target, nil); err != nil {
		t.Fatal(err)
	}
	if gone, err := access.Check(access.Sandbox{Group: s.SID}, target, access.Create); err != nil {
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
	if still, err := access.Check(access.Sandbox{Group: s.SID}, target, access.Create); err != nil {
		t.Fatal(err)
	} else if still.Allowed {
		t.Fatal("the fast path applied the permission; the test no longer covers the repair")
	}

	// Repair acts on the file system instead.
	if err := s.Ensure(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	back, err := access.Check(access.Sandbox{Group: s.SID}, target, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Allowed {
		t.Errorf("init would not have repaired the sandbox: %s", back.Reason)
	}
}

// TestReapplySkipsAFreshDisjointGrant keeps the first init from sweeping a
// newly recorded tree twice. The revoke below makes a second Apply observable:
// a repair pass would restore the permission, while the optimized pass leaves
// the deliberately removed entry absent.
func TestReapplySkipsAFreshDisjointGrant(t *testing.T) {
	s := newState(t)
	target := tempDir(t)
	s.BeginInit()
	defer s.EndInit()
	if err := s.Ensure(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := grant.Revoke(s.SID, target, nil); err != nil {
		t.Fatal(err)
	}
	if err := Reapply(s); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(access.Sandbox{Group: s.SID}, target, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Fatal("a fresh disjoint grant was applied a second time")
	}
}

func TestFreshGrantStillReappliesWhenTreesOverlap(t *testing.T) {
	parent := tempDir(t)
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newState(t)
	if err := s.Add(parent, grant.RW); err != nil {
		t.Fatal(err)
	}
	s.BeginInit()
	defer s.EndInit()
	if err := s.Ensure(child, grant.RW); err != nil {
		t.Fatal(err)
	}
	if !overlapsAnother(s, s.Grants[len(s.Grants)-1]) {
		t.Fatal("a fresh child grant was treated as disjoint from its parent")
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
	if err := grant.Revoke(s.SID, byHand, nil); err != nil {
		t.Fatal(err)
	}
	if gone, err := access.Check(access.Sandbox{Group: s.SID}, byHand, access.Create); err != nil {
		t.Fatal(err)
	} else if gone.Allowed {
		t.Fatal("the permission survived being revoked")
	}

	if err := Reapply(s); err != nil {
		t.Fatal(err)
	}
	back, err := access.Check(access.Sandbox{Group: s.SID}, byHand, access.Create)
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
