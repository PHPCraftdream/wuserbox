package grants

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wuserbox/internal/policy/config"
	"wuserbox/internal/policy/grant"
	"wuserbox/internal/policy/state"
)

const testAccount = "S-1-5-21-1111111111-2222222222-3333333333-778899"

// TestMain loads the ktav parser before any test moves LOCALAPPDATA. The
// parser caches a native library under that directory and keeps it open, which
// would otherwise leave a temporary directory undeletable.
func TestMain(m *testing.M) {
	warm, err := os.CreateTemp("", "wuserbox-warm-*.ktav")
	if err == nil {
		warm.WriteString("projects: [\n]\n")
		warm.Close()
		os.Setenv(config.EnvPath, warm.Name())
		config.Load() // reaches the parser, which loads its library once
		os.Remove(warm.Name())
		os.Unsetenv(config.EnvPath)
	}
	os.Exit(m.Run())
}

func newState(t *testing.T) *state.State {
	t.Helper()
	t.Setenv("LOCALAPPDATA", t.TempDir())
	return &state.State{
		Group: "wub-grants-test",
		SID:   testAccount,
		Dir:   t.TempDir(),
		Temp:  t.TempDir(),
	}
}

func TestExtraGrantsBothKinds(t *testing.T) {
	s := newState(t)
	writable, readable := t.TempDir(), t.TempDir()
	if err := Extra(s, []string{writable}, []string{readable}); err != nil {
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
	dir := t.TempDir()
	shellStyle := "/" + strings.ToLower(dir[:1]) + filepath.ToSlash(dir[2:])
	if err := Extra(s, []string{shellStyle}, nil); err != nil {
		t.Fatal(err)
	}
	if !s.Has(dir) {
		t.Errorf("recorded %+v, want %s", s.Grants, dir)
	}
}

func TestFromConfigSkipsDirectoriesThatAreGone(t *testing.T) {
	s := newState(t)
	present := t.TempDir()
	missing := filepath.Join(t.TempDir(), "removed")
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))

	rules := &config.Config{Projects: []config.Rule{{Dir: s.Dir, RW: []string{present, missing}}}}
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}
	if err := FromConfig(s); err != nil {
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
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "none.ktav"))
	if err := FromConfig(s); err != nil {
		t.Fatal(err)
	}
	if len(s.Grants) != 0 {
		t.Errorf("recorded %+v", s.Grants)
	}
}

func TestProtectSettingsLocksTheRulesFile(t *testing.T) {
	s := newState(t)
	rulesPath := filepath.Join(t.TempDir(), "rules.ktav")
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
	home := t.TempDir()
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
