package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

func useTempConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(tempDir(t), "wuserbox.ktav")
	t.Setenv(EnvPath, path)
	return path
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	path := useTempConfig(t)
	want := &Config{Projects: []Rule{
		{Dir: `C:\projects\app`, RW: []string{`C:\projects\tools`, `C:\projects\logs`}},
		{Dir: `C:\projects\second`, RO: []string{`C:\shared`}},
	}}
	if err := want.Save(); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(text), `\`) {
		t.Errorf("backslashes survived into the file, ktav would read them as escapes:\n%s", text)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Projects) != 2 {
		t.Fatalf("got %d projects, want 2", len(got.Projects))
	}
	if !SamePath(got.Projects[0].Dir, `C:\projects\app`) {
		t.Errorf("dir came back as %q", got.Projects[0].Dir)
	}
	if len(got.Projects[0].RW) != 2 || !SamePath(got.Projects[0].RW[1], `C:\projects\logs`) {
		t.Errorf("rw list came back as %v", got.Projects[0].RW)
	}
	if len(got.Projects[1].RO) != 1 {
		t.Errorf("ro list came back as %v", got.Projects[1].RO)
	}
}

func TestLoadWithoutFileIsEmpty(t *testing.T) {
	useTempConfig(t)
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Projects) != 0 {
		t.Errorf("expected no projects, got %v", got.Projects)
	}
}

func TestLoadRejectsBrokenFile(t *testing.T) {
	path := useTempConfig(t)
	if err := os.WriteFile(path, []byte("projects: [ { dir: "), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Error("expected a parse error")
	}
}

func TestAddIsIdempotentAcrossSpellings(t *testing.T) {
	c := &Config{}
	rule := c.RuleFor(`C:\app`, true)
	if !rule.Add(`C:\tools`, "rw") {
		t.Fatal("first add should report a change")
	}
	if rule.Add(`c:/tools`, grant.RW) {
		t.Error("the same directory was added twice")
	}
	if len(rule.RW) != 1 {
		t.Errorf("rw list is %v", rule.RW)
	}
}

func TestRemoveReportsWhetherAnythingChanged(t *testing.T) {
	c := &Config{Projects: []Rule{{Dir: `C:\app`, RW: []string{`C:\tools`}, RO: []string{`C:\shared`}}}}
	rule := c.RuleFor(`C:\app`, false)
	if !rule.Remove(`c:/shared`) {
		t.Error("removing a listed directory should report a change")
	}
	if rule.Remove(`C:\nothing`) {
		t.Error("removing an unlisted directory should report no change")
	}
	if len(rule.RW) != 1 || len(rule.RO) != 0 {
		t.Errorf("lists are rw=%v ro=%v", rule.RW, rule.RO)
	}
}

func TestRuleForCreatesOnlyWhenAsked(t *testing.T) {
	c := &Config{}
	if c.RuleFor(`C:\app`, false) != nil {
		t.Error("expected no rule")
	}
	if c.RuleFor(`C:\app`, true) == nil || len(c.Projects) != 1 {
		t.Error("expected a rule to be created")
	}
	if c.RuleFor(`C:\APP\`, true); len(c.Projects) != 1 {
		t.Errorf("a different spelling created a second rule: %v", c.Projects)
	}
}

func TestGrantsForMapsKinds(t *testing.T) {
	c := &Config{Projects: []Rule{{Dir: `C:\app`, RW: []string{`C:/tools`}, RO: []string{`C:/shared`}}}}
	grants := c.GrantsFor(`C:\app`)
	if len(grants) != 2 {
		t.Fatalf("got %v", grants)
	}
	if grants[0].Kind != grant.RW || grants[0].Path != `C:\tools` {
		t.Errorf("rw grant is %+v", grants[0])
	}
	if grants[1].Kind != grant.RO || grants[1].Path != `C:\shared` {
		t.Errorf("ro grant is %+v", grants[1])
	}
	if c.GrantsFor(`C:\elsewhere`) != nil {
		t.Error("expected no grants for an unlisted project")
	}
}

func TestRulesMatchAnyPathSpelling(t *testing.T) {
	useTempConfig(t)
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	project := filepath.Join(home, "project")
	tools := filepath.Join(home, "tools")
	for _, dir := range []string{project, tools} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	drive := strings.ToLower(project[:1])
	shellStyle := "/" + drive + filepath.ToSlash(project[2:])

	// The file was written by hand, in the spelling a person would use.
	rules := &Config{Projects: []Rule{{
		Dir: filepath.ToSlash(project),
		RW:  []string{filepath.ToSlash(tools), "~/tools", "%USERPROFILE%/tools"},
	}}}
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{
		project,
		strings.ToUpper(project),
		filepath.ToSlash(project),
		project + `\`,
		shellStyle,
		"~/project",
		"%USERPROFILE%/project",
	} {
		if loaded.RuleFor(spelling, false) == nil {
			t.Errorf("the rule was not found for %q", spelling)
		}
	}
	grants := loaded.GrantsFor(project)
	if len(grants) != 3 {
		t.Fatalf("got %d grants, want 3", len(grants))
	}
	for _, g := range grants {
		if !strings.EqualFold(g.Path, tools) {
			t.Errorf("a path resolved to %q, want %q", g.Path, tools)
		}
	}
}

func TestRuleForStillMatchesAVanishedDirectory(t *testing.T) {
	rules := &Config{Projects: []Rule{{Dir: "C:/gone/project"}}}
	if rules.RuleFor(`C:\gone\project`, false) == nil {
		t.Error("a rule for a directory that no longer exists should still match")
	}
}

// TestAddMovesAPathBetweenTheLists is the regression guard for a rule that
// contradicted itself: narrowing a directory used to leave it in both lists,
// and the reader would apply the writable entry and then the readable one, so
// write access disappeared without a word.
func TestAddMovesAPathBetweenTheLists(t *testing.T) {
	c := &Config{}
	rule := c.RuleFor(`C:\app`, true)
	rule.Add(`C:\tools`, grant.RW)

	if !rule.Add(`c:/tools`, grant.RO) {
		t.Error("narrowing a directory should report a change")
	}
	if len(rule.RW) != 0 {
		t.Errorf("the writable list still holds %v", rule.RW)
	}
	if len(rule.RO) != 1 {
		t.Errorf("the readable list holds %v", rule.RO)
	}
	if kind, listed := rule.Kind(`C:\TOOLS`); !listed || kind != grant.RO {
		t.Errorf("the path reads as %q, listed=%v", kind, listed)
	}

	// And back again.
	if !rule.Add(`C:\tools`, grant.RW) {
		t.Error("widening a directory should report a change")
	}
	if len(rule.RO) != 0 || len(rule.RW) != 1 {
		t.Errorf("lists are rw=%v ro=%v", rule.RW, rule.RO)
	}
}

func TestKindReportsAnUnlistedPath(t *testing.T) {
	rule := &Rule{Dir: `C:\app`}
	if _, listed := rule.Kind(`C:\nothing`); listed {
		t.Error("an unlisted path was reported as listed")
	}
}

// TestRulesCannotContradictThemselvesThroughTheCommand checks the same thing
// one level up, the way a user would hit it.
func TestRulesCannotContradictThemselvesThroughTheCommand(t *testing.T) {
	useTempConfig(t)
	c := &Config{}
	rule := c.RuleFor(`C:\app`, true)
	rule.Add(`C:\tools`, grant.RW)
	rule.Add(`C:\tools`, grant.RO)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	grants := loaded.GrantsFor(`C:\app`)
	if len(grants) != 1 {
		t.Fatalf("one directory produced %d grants: %+v", len(grants), grants)
	}
	if grants[0].Kind != grant.RO {
		t.Errorf("the kept grant is %q, want %q", grants[0].Kind, grant.RO)
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
