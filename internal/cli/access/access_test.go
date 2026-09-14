package access

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/lock"
	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
)

// TestMain loads the rules parser before any test moves LOCALAPPDATA. The
// parser caches a native library under that directory and keeps it open, which
// would otherwise leave a temporary directory undeletable.
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

// TestTheRulesFileKeepsBothRulesWrittenAtOnce is the regression guard for two
// add-dir commands running together. Each used to load the rules file, add its
// own directory and save the whole file back, so the one that finished second
// wrote a file built before the first one's change and that rule was gone.
func TestTheRulesFileKeepsBothRulesWrittenAtOnce(t *testing.T) {
	t.Setenv("LOCALAPPDATA", tempDir(t))
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))
	projects := []string{tempDir(t), tempDir(t)}
	directories := []string{tempDir(t), tempDir(t)}

	var wg sync.WaitGroup
	failures := make(chan error, len(projects))
	for i := range projects {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			failures <- lock.Hold(lock.Rules, func() error {
				rules, err := config.Load()
				if err != nil {
					return err
				}
				rules.RuleFor(projects[i], true).Add(directories[i], grant.RW)
				// The window the other command used to slip into.
				time.Sleep(20 * time.Millisecond)
				return rules.Save()
			})
		}(i)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}

	rules, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	for i, project := range projects {
		rule := rules.RuleFor(project, false)
		if rule == nil {
			t.Errorf("the rule for %s is gone", project)
			continue
		}
		if _, listed := rule.Kind(directories[i]); !listed {
			t.Errorf("%s is missing from the rule for %s", directories[i], project)
		}
	}
}

// TestAddDirHoldsTheRulesFile checks the command itself, not only the
// mechanism it uses: add-dir has to take the rules lock, or serializing the
// writes protects nothing.
func TestAddDirHoldsTheRulesFile(t *testing.T) {
	t.Setenv("LOCALAPPDATA", tempDir(t))
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))
	project, target := tempDir(t), tempDir(t)

	release, err := hold(lock.Rules)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- AddDir([]string{target, "--dir", project}) }()
	select {
	case err := <-finished:
		release()
		t.Fatalf("add-dir wrote the rules file while it was held: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	release()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("add-dir never finished after the rules file was let go")
	}

	rules, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	rule := rules.RuleFor(project, false)
	if rule == nil {
		t.Fatal("the rule was not written")
	}
	if _, listed := rule.Kind(target); !listed {
		t.Errorf("%s is missing from the rule for %s", target, project)
	}
}

// hold takes a lock in the background and returns how to let it go, so a test
// can watch a command wait for it.
func hold(name string) (func(), error) {
	taken := make(chan error, 1)
	done := make(chan struct{})
	released := make(chan struct{})
	go func() {
		_ = lock.Hold(name, func() error {
			taken <- nil
			<-done
			return nil
		})
		close(released)
	}()
	if err := <-taken; err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			<-released
		})
	}, nil
}

// TestARuleAndItsPermissionCannotDisagree is the regression guard for the gap
// between writing a rule and applying it. add-dir used to take one lock for the
// rules file and another for the sandbox, and a remove-dir arriving between the
// two deleted the rule and finished; the grant that followed then left a
// writable directory that no rule accounted for, with both commands reporting
// success.
func TestARuleAndItsPermissionCannotDisagree(t *testing.T) {
	t.Setenv("LOCALAPPDATA", tempDir(t))
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))
	project, shared := tempDir(t), tempDir(t)
	name, _, err := sandbox.Name(project)
	if err != nil {
		t.Fatal(err)
	}
	s := &state.State{
		Group: name,
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-242424",
		Dir:   project,
		Temp:  tempDir(t),
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// Something else is working on this sandbox, so add-dir gets as far as the
	// rule and then has to wait.
	releaseSandbox, err := hold(name)
	if err != nil {
		t.Fatal(err)
	}
	added := make(chan error, 1)
	go func() { added <- AddDir([]string{shared, "--dir", project}) }()
	select {
	case err := <-added:
		releaseSandbox()
		t.Fatalf("add-dir finished without waiting for the sandbox: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	// remove-dir must not slip past it. If it can, it deletes the rule that
	// add-dir has already written and the grant still lands afterwards.
	removed := make(chan error, 1)
	go func() { removed <- RemoveDir([]string{shared, "--dir", project}) }()
	select {
	case err := <-removed:
		releaseSandbox()
		t.Fatalf("remove-dir went ahead while add-dir was half done: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	releaseSandbox()
	for _, done := range []chan error{added, removed} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a command never finished after the sandbox was let go")
		}
	}

	// Whichever order they finished in, the rules file and the permissions
	// have to say the same thing.
	rules, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	if rule := rules.RuleFor(project, false); rule != nil {
		_, listed = rule.Kind(shared)
	}
	final, err := state.Load(name)
	if err != nil {
		t.Fatal(err)
	}
	if listed != final.Has(shared) {
		t.Errorf("the rules file says %v and the sandbox says %v about %s",
			listed, final.Has(shared), shared)
	}
}
