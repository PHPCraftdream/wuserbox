package plan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

// TestMain loads the rules parser before any test moves the environment, so
// the native library it keeps open is not cached under a temporary directory.
func TestMain(m *testing.M) {
	warm, err := os.CreateTemp("", "wuserbox-warm-*.ktav")
	if err == nil {
		_, _ = warm.WriteString("projects: [\n]\n")
		warm.Close()
		os.Setenv(config.EnvPath, warm.Name())
		_, _ = config.Load()
		os.Remove(warm.Name())
		os.Unsetenv(config.EnvPath)
	}
	os.Exit(m.Run())
}

func emptyProfile(t *testing.T) string {
	t.Helper()
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))
	return home
}

func TestForAlwaysCoversTheProjectAndItsTemp(t *testing.T) {
	emptyProfile(t)
	project, temp := tempDir(t), tempDir(t)
	prepared, err := For(Input{Group: "wub-test", Dir: project, Temp: temp})
	if err != nil {
		t.Fatal(err)
	}
	sources := map[Source]string{}
	for _, entry := range prepared.Entries {
		sources[entry.Source] = entry.Path
		if entry.Kind != grant.RW {
			t.Errorf("%s is %q, want %q", entry.Path, entry.Kind, grant.RW)
		}
	}
	if sources[FromProject] != project {
		t.Errorf("the project is %q", sources[FromProject])
	}
	if sources[FromTemp] != temp {
		t.Errorf("the temp directory is %q", sources[FromTemp])
	}
}

func TestForRecordsWhereEachDirectoryCameFrom(t *testing.T) {
	home := emptyProfile(t)
	agent := filepath.Join(home, ".claude")
	if err := os.Mkdir(agent, 0o755); err != nil {
		t.Fatal(err)
	}
	fromRules, fromFlag := tempDir(t), tempDir(t)
	rules := &config.Config{Projects: []config.Rule{{Dir: tempDir(t), RW: []string{fromRules}}}}
	rules.Projects[0].Dir = filepath.Clean(rules.Projects[0].Dir)
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}
	prepared, err := For(Input{
		Group: "wub-test", Dir: rules.Projects[0].Dir, Temp: tempDir(t),
		RW: []string{fromFlag},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Source{}
	for _, entry := range prepared.Entries {
		got[strings.ToLower(entry.Path)] = entry.Source
	}
	for path, want := range map[string]Source{
		strings.ToLower(agent):     FromPreset,
		strings.ToLower(fromRules): FromRules,
		strings.ToLower(fromFlag):  FromFlags,
	} {
		if got[path] != want {
			t.Errorf("%s came from %q, want %q", path, got[path], want)
		}
	}
}

func TestForLetsALaterSourceWin(t *testing.T) {
	emptyProfile(t)
	shared := tempDir(t)
	rules := &config.Config{Projects: []config.Rule{{Dir: `C:\app`, RW: []string{shared}}}}
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}
	// The same directory arrives twice: once from the rules, once narrowed on
	// the command line. The plan has to show the access that would end up in
	// force, not both.
	prepared, err := For(Input{
		Group: "wub-test", Dir: `C:\app`, Temp: tempDir(t),
		RO: []string{shared},
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, entry := range prepared.Entries {
		if strings.EqualFold(entry.Path, shared) {
			seen++
			if entry.Kind != grant.RO || entry.Source != FromFlags {
				t.Errorf("the entry is %q from %q", entry.Kind, entry.Source)
			}
		}
	}
	if seen != 1 {
		t.Errorf("the directory appears %d times", seen)
	}
}

func TestForSkipsTheProfileRootUnlessAsked(t *testing.T) {
	home := emptyProfile(t)
	withoutIt, err := For(Input{Group: "g", Dir: tempDir(t), Temp: tempDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range withoutIt.Entries {
		if strings.EqualFold(entry.Path, home) {
			t.Error("the profile root is in the plan by default")
		}
	}
	withIt, err := For(Input{Group: "g", Dir: tempDir(t), Temp: tempDir(t), HomeWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, entry := range withIt.Entries {
		if strings.EqualFold(entry.Path, home) {
			found = true
		}
	}
	if !found {
		t.Error("--home-writes did not put the profile root in the plan")
	}
	if len(withIt.Reserved) == 0 {
		t.Error("nothing would be reserved, so the sandbox could claim a name first")
	}
}

// TestForSurfacesAnExistingGrantNothingElseExplains is the regression guard
// for --dry-run on an already-built sandbox. A directory handed over once
// with --grant lives only in the sandbox's own record, never in the rules
// file, so a plan built solely from this command line's flags left it out
// entirely.
func TestForSurfacesAnExistingGrantNothingElseExplains(t *testing.T) {
	emptyProfile(t)
	grantedOnce := tempDir(t)
	prepared, err := For(Input{
		Group: "wub-test", Dir: tempDir(t), Temp: tempDir(t),
		Existing: []grant.Spec{{Path: grantedOnce, Kind: grant.RW}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range prepared.Entries {
		if strings.EqualFold(entry.Path, grantedOnce) {
			if entry.Source != FromState {
				t.Errorf("the entry is explained as %q, want %q", entry.Source, FromState)
			}
			return
		}
	}
	t.Error("a directory only the existing record knows about is missing from the plan")
}

// TestForLetsAFreshSourceOverrideAnExistingOne keeps an existing entry from
// shadowing a source that would still apply if the sandbox were built again
// now.
func TestForLetsAFreshSourceOverrideAnExistingOne(t *testing.T) {
	emptyProfile(t)
	project := tempDir(t)
	prepared, err := For(Input{
		Group: "wub-test", Dir: project, Temp: tempDir(t),
		Existing: []grant.Spec{{Path: project, Kind: grant.RO}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range prepared.Entries {
		if strings.EqualFold(entry.Path, project) {
			if entry.Source != FromProject || entry.Kind != grant.RW {
				t.Errorf("the project entry is %q/%q, want %q/%q",
					entry.Kind, entry.Source, grant.RW, FromProject)
			}
		}
	}
}

func TestWritableLeavesOutReadOnlyEntries(t *testing.T) {
	p := Plan{Entries: []Entry{
		{Path: `C:\a`, Kind: grant.RW},
		{Path: `C:\b`, Kind: grant.RO},
		{Path: `C:\c`, Kind: grant.File},
	}}
	writable := p.Writable()
	if len(writable) != 2 {
		t.Fatalf("got %v", writable)
	}
}

func TestRenderSaysTheSameThingBothWays(t *testing.T) {
	p := Plan{Group: "wub-test", Dir: `C:\app`, Temp: `C:\temp`, Entries: []Entry{
		{Path: `C:\app`, Kind: grant.RW, Source: FromProject},
	}}
	lines, err := Render(p, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"wub-test", `C:\app`, `C:\temp`, "rw", "project"} {
		if !strings.Contains(lines, want) {
			t.Errorf("the text does not mention %q:\n%s", want, lines)
		}
	}
	encoded, err := Render(p, true)
	if err != nil {
		t.Fatal(err)
	}
	var back Plan
	if err := json.Unmarshal([]byte(encoded), &back); err != nil {
		t.Fatalf("the JSON does not parse: %v", err)
	}
	if back.Group != p.Group || len(back.Entries) != 1 || back.Entries[0].Source != FromProject {
		t.Errorf("the JSON lost something: %+v", back)
	}
}

func TestRenderActionsHandlesAnEmptyList(t *testing.T) {
	lines, err := RenderActions(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lines, "nothing to do") {
		t.Errorf("got %q", lines)
	}
	encoded, err := RenderActions(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Actions []Action `json:"actions"`
	}
	if err := json.Unmarshal([]byte(encoded), &back); err != nil {
		t.Fatalf("the JSON does not parse: %v", err)
	}
	if back.Actions == nil || len(back.Actions) != 0 {
		t.Errorf("an empty list should encode as [], got %v", back.Actions)
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
