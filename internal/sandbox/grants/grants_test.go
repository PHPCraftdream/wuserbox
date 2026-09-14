package grants

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
)

const testAccount = "S-1-5-21-1111111111-2222222222-3333333333-778899"

// TestMain loads the ktav parser before any test moves LOCALAPPDATA. The
// parser caches a native library under that directory and keeps it open, which
// would otherwise leave a temporary directory undeletable.
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

func newState(t *testing.T) *state.State {
	t.Helper()
	t.Setenv("LOCALAPPDATA", tempDir(t))
	return &state.State{
		Group: "wub-grants-test",
		SID:   testAccount,
		Dir:   tempDir(t),
		Temp:  tempDir(t),
	}
}

func TestExtraGrantsBothKinds(t *testing.T) {
	s := newState(t)
	writable, readable := tempDir(t), tempDir(t)
	if err := Extra(s, []string{writable}, []string{readable}, false); err != nil {
		t.Fatal(err)
	}
	if len(s.Grants) != 2 {
		t.Fatalf("recorded %+v", s.Grants)
	}
	if s.Grants[0].Kind != grant.RW || s.Grants[1].Kind != grant.RO {
		t.Errorf("kinds are %q and %q", s.Grants[0].Kind, s.Grants[1].Kind)
	}
}

func TestExtraAcceptsShellStylePaths(t *testing.T) {
	s := newState(t)
	dir := tempDir(t)
	shellStyle := "/" + strings.ToLower(dir[:1]) + filepath.ToSlash(dir[2:])
	if err := Extra(s, []string{shellStyle}, nil, false); err != nil {
		t.Fatal(err)
	}
	if !s.Has(dir) {
		t.Errorf("recorded %+v, want %s", s.Grants, dir)
	}
}

func TestFromConfigSkipsDirectoriesThatAreGone(t *testing.T) {
	s := newState(t)
	present := tempDir(t)
	missing := filepath.Join(tempDir(t), "removed")
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))

	rules := &config.Config{Projects: []config.Rule{{Dir: s.Dir, RW: []string{present, missing}}}}
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}
	if err := FromConfig(s, false); err != nil {
		t.Fatal(err)
	}
	if !s.Has(present) {
		t.Error("the directory that exists was not granted")
	}
	if s.Has(missing) {
		t.Error("a directory that no longer exists was granted")
	}
}

func TestFromConfigIsHarmlessWithoutRules(t *testing.T) {
	s := newState(t)
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "none.ktav"))
	if err := FromConfig(s, false); err != nil {
		t.Fatal(err)
	}
	if len(s.Grants) != 0 {
		t.Errorf("recorded %+v", s.Grants)
	}
}

func TestProtectSettingsLocksTheRulesFile(t *testing.T) {
	s := newState(t)
	rulesPath := filepath.Join(tempDir(t), "rules.ktav")
	t.Setenv(config.EnvPath, rulesPath)
	if err := (&config.Config{}).Save(); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if err := ProtectSettings(s); err != nil {
		t.Fatal(err)
	}
	// The owner keeps full access, which is what makes the tool usable.
	if err := os.WriteFile(rulesPath, []byte("projects: []\n"), 0o644); err != nil {
		t.Errorf("the owner lost access to the rules: %v", err)
	}
}

func TestRefuseHomeFilesLeavesGrantedFilesAlone(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	s := newState(t)

	granted := filepath.Join(home, ".agent.json")
	companion := filepath.Join(home, ".agent.json.tmp.1234")
	other := filepath.Join(home, ".bashrc")
	for _, f := range []string{granted, companion, other} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Add(granted, grant.File); err != nil {
		t.Fatal(err)
	}
	if err := RefuseHomeFiles(s); err != nil {
		t.Fatal(err)
	}
	// Nothing is recorded as a grant; refusals are applied directly.
	if len(s.Grants) != 1 {
		t.Errorf("refusals leaked into the record: %+v", s.Grants)
	}
}

func TestIsAllowedMatchesCompanionFiles(t *testing.T) {
	allowed := []string{`C:\Users\me\.agent.json`}
	cases := map[string]bool{
		`C:\Users\me\.agent.json`:          true,
		`C:\USERS\ME\.AGENT.JSON`:          true,
		`C:\Users\me\.agent.json.tmp.9182`: true,
		`C:\Users\me\.agent.jsonx`:         false,
		`C:\Users\me\.bashrc`:              false,
	}
	for path, want := range cases {
		if got := isAllowed(path, allowed); got != want {
			t.Errorf("isAllowed(%q) = %v, want %v", path, got, want)
		}
	}
}

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

func TestProtectSettingsCreatesTheRulesFile(t *testing.T) {
	// A sandbox that may create files in the profile root must not be able to
	// write the rules file first: it would grant itself directories on the
	// next ordinary run.
	rulesPath := filepath.Join(tempDir(t), "rules.ktav")
	t.Setenv(config.EnvPath, rulesPath)
	t.Setenv("USERPROFILE", tempDir(t))
	s := newState(t)

	if _, err := os.Stat(rulesPath); err == nil {
		t.Fatal("the rules file exists before the test starts")
	}
	if err := ProtectSettings(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rulesPath); err != nil {
		t.Fatalf("the rules file was not created: %v", err)
	}
	rules, err := config.Load()
	if err != nil {
		t.Fatalf("the created rules file does not parse: %v", err)
	}
	if len(rules.Projects) != 0 {
		t.Errorf("the created rules file is not empty: %+v", rules.Projects)
	}
}

func TestReserveSensitiveNamesTakesTheNamesFirst(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))

	unguarded, err := ReserveSensitiveNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(unguarded) != 0 {
		t.Errorf("nothing should be unreachable in an empty profile: %v", unguarded)
	}
	for _, name := range []string{".bashrc", ".gitconfig", ".netrc", ".bash_profile"} {
		if _, err := os.Stat(filepath.Join(home, name)); err != nil {
			t.Errorf("%s was not reserved: %v", name, err)
		}
	}
}

func TestReserveSensitiveNamesKeepsExistingContent(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	existing := filepath.Join(home, ".gitconfig")
	if err := os.WriteFile(existing, []byte("[user]\n\tname = someone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveSensitiveNames(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(existing)
	if err != nil || !strings.Contains(string(data), "someone") {
		t.Errorf("an existing file was overwritten: %q (%v)", data, err)
	}
}

func TestReserveSensitiveNamesReportsWhatItCannotTake(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	if err := os.WriteFile(filepath.Join(home, ".profile"), []byte("export X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unguarded, err := ReserveSensitiveNames()
	if err != nil {
		t.Fatal(err)
	}
	var reported bool
	for _, path := range unguarded {
		if filepath.Base(path) == ".bash_profile" {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the caller was not told about .bash_profile: %v", unguarded)
	}
	if _, err := os.Stat(filepath.Join(home, ".bash_profile")); err == nil {
		t.Error(".bash_profile was created and now hides the real .profile")
	}
}

// TestReserveSensitiveNamesKeepsDirectoriesDirectories is the regression guard
// for a fix that was worse than the problem: taking .ssh as an empty file
// would break every tool that expects a directory there, inside the sandbox
// and outside it.
func TestReserveSensitiveNamesKeepsDirectoriesDirectories(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))

	if _, err := ReserveSensitiveNames(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".ssh", ".gnupg", ".aws", ".azure", ".docker", ".kube"} {
		info, err := os.Stat(filepath.Join(home, name))
		if err != nil {
			t.Errorf("%s was not reserved: %v", name, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s was taken as a file; a tool expecting a directory would break", name)
		}
	}
	for _, name := range []string{".bashrc", ".gitconfig", ".netrc"} {
		info, err := os.Stat(filepath.Join(home, name))
		if err != nil {
			t.Errorf("%s was not reserved: %v", name, err)
			continue
		}
		if info.IsDir() {
			t.Errorf("%s was taken as a directory", name)
		}
	}
}

func TestReserveSensitiveNamesLeavesAnExistingDirectoryAlone(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	keys := filepath.Join(home, ".ssh")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "id_ed25519"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveSensitiveNames(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(keys, "id_ed25519")); err != nil {
		t.Errorf("an existing key was lost: %v", err)
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
	allowed, err := access.Check(s.SID, target, access.Create, false)
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
	if gone, err := access.Check(s.SID, target, access.Create, false); err != nil {
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
	if still, err := access.Check(s.SID, target, access.Create, false); err != nil {
		t.Fatal(err)
	} else if still.Allowed {
		t.Fatal("the fast path applied the permission; the test no longer covers the repair")
	}

	// Repair acts on the file system instead.
	if err := s.Ensure(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	back, err := access.Check(s.SID, target, access.Create, false)
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
	if gone, err := access.Check(s.SID, byHand, access.Create, false); err != nil {
		t.Fatal(err)
	} else if gone.Allowed {
		t.Fatal("the permission survived being revoked")
	}

	if err := Reapply(s); !grant.Applied(err) {
		t.Fatal(err)
	}
	back, err := access.Check(s.SID, byHand, access.Create, false)
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
	refused, err := access.Check(testAccount, agent, access.Create, false)
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
	answer, err := access.Check(testAccount, agent, access.Create, false)
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

// tempDir is t.TempDir() with the path reduced to one spelling, the way every
// command reduces the paths it is given. Some machines hand out a temporary
// directory under a shortened name, and comparing one spelling against another
// would fail there for a reason that has nothing to do with what is being
// tested.
func tempDir(t *testing.T) string {
	t.Helper()
	resolved, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
