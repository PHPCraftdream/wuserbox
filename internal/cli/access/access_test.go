package access

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
)

func TestParseTargetResolvesAnyPathSpelling(t *testing.T) {
	dir := tempDir(t)
	project := tempDir(t)
	drive := strings.ToLower(dir[:1])
	shellStyle := "/" + drive + filepath.ToSlash(dir[2:])

	for _, spelling := range []string{dir, filepath.ToSlash(dir), shellStyle, `"` + dir + `"`} {
		got, err := parseTarget("grant", []string{spelling, "--dir", project})
		if err != nil {
			t.Errorf("%s: %v", spelling, err)
			continue
		}
		if !strings.EqualFold(got.path, dir) {
			t.Errorf("%s resolved to %q, want %q", spelling, got.path, dir)
		}
		if got.kind != grant.RW {
			t.Errorf("%s: kind is %q, want %q", spelling, got.kind, grant.RW)
		}
	}
}

func TestParseTargetReadsTheReadOnlySwitch(t *testing.T) {
	got, err := parseTarget("grant", []string{tempDir(t), "--ro", "--dir", tempDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	if got.kind != grant.RO {
		t.Errorf("kind is %q", got.kind)
	}
}

func TestParseTargetNeedsExactlyOneDirectory(t *testing.T) {
	for _, args := range [][]string{{}, {"a", "b"}} {
		if _, err := parseTarget("grant", args); err == nil {
			t.Errorf("%v should have been rejected", args)
		}
	}
}

func TestTargetArgumentsRoundTrip(t *testing.T) {
	original := target{path: `C:\tools`, project: `C:\project`, kind: grant.RO}
	args := original.args("grant")
	if args[0] != "grant" {
		t.Fatalf("rebuilt arguments start with %q", args[0])
	}
	rebuilt, err := parseTarget("grant", args[1:])
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.kind != original.kind {
		t.Errorf("kind changed to %q", rebuilt.kind)
	}
	if !strings.EqualFold(rebuilt.path, original.path) {
		t.Errorf("path changed to %q", rebuilt.path)
	}
}

func TestLoadReportsAnUninitializedSandbox(t *testing.T) {
	t.Setenv("LOCALAPPDATA", tempDir(t))
	_, err := load(tempDir(t))
	if err == nil || !strings.Contains(err.Error(), "wuserbox init") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestAddDirRejectsSomethingThatIsNotADirectory(t *testing.T) {
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))
	file := filepath.Join(tempDir(t), "a-file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := AddDir([]string{file, "--dir", tempDir(t)})
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("got %v", err)
	}
}

func TestAddDirThenRemoveDirEditTheRules(t *testing.T) {
	// LOCALAPPDATA is left alone: the ktav parser caches a library there and
	// keeps it open, which would break the temporary directory cleanup.
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))
	project := tempDir(t)
	tools := tempDir(t)

	if err := AddDir([]string{tools, "--dir", project}); err != nil {
		t.Fatalf("add-dir: %v", err)
	}
	rules, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.GrantsFor(project)) != 1 {
		t.Fatalf("the rules hold %+v", rules.Projects)
	}

	if err := RemoveDir([]string{tools, "--dir", project}); err != nil {
		t.Fatalf("remove-dir: %v", err)
	}
	if rules, err = config.Load(); err != nil {
		t.Fatal(err)
	}
	if len(rules.GrantsFor(project)) != 0 {
		t.Errorf("the rule survived removal: %+v", rules.Projects)
	}
}

func TestRemoveDirReportsAnUnlistedDirectory(t *testing.T) {
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))
	err := RemoveDir([]string{tempDir(t), "--dir", tempDir(t)})
	if err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Errorf("got %v", err)
	}
}

// TestPlannedSeesTheSandboxAndNotOnlyTheRules is the regression guard for a
// preview that said "nothing to do" for a command that went on to change an
// access control entry: the rules already agreed, but the permission the
// sandbox held did not.
func TestPlannedSeesTheSandboxAndNotOnlyTheRules(t *testing.T) {
	project, tools := tempDir(t), tempDir(t)
	rules := &config.Config{Projects: []config.Rule{{Dir: project, RO: []string{tools}}}}
	held := &state.State{
		Group:  "wub-preview-test",
		SID:    "S-1-5-21-1111111111-2222222222-3333333333-141414",
		Dir:    project,
		Grants: []grant.Spec{{Path: tools, Kind: grant.RW}},
	}
	asked := target{path: tools, project: project, kind: grant.RO}

	actions := planned(rules, held, asked)
	if len(actions) == 0 {
		t.Fatal("the preview reported no change, but the permission would be narrowed")
	}
	var mentioned bool
	for _, action := range actions {
		if strings.Contains(action.Detail, "rw to ro") {
			mentioned = true
		}
	}
	if !mentioned {
		t.Errorf("the preview does not say the access would change: %+v", actions)
	}
}

func TestPlannedSaysNothingWhenBothAgree(t *testing.T) {
	project, tools := tempDir(t), tempDir(t)
	rules := &config.Config{Projects: []config.Rule{{Dir: project, RW: []string{tools}}}}
	held := &state.State{
		Group:  "wub-preview-test",
		Dir:    project,
		Grants: []grant.Spec{{Path: tools, Kind: grant.RW}},
	}
	asked := target{path: tools, project: project, kind: grant.RW}
	if actions := planned(rules, held, asked); len(actions) != 0 {
		t.Errorf("nothing would change, yet the preview lists %+v", actions)
	}
}

func TestPlannedWithoutASandboxOnlyChangesTheRules(t *testing.T) {
	project, tools := tempDir(t), tempDir(t)
	actions := planned(&config.Config{}, nil, target{path: tools, project: project, kind: grant.RW})
	if len(actions) != 1 || actions[0].Does != "record" {
		t.Errorf("got %+v", actions)
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
