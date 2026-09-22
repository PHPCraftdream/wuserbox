// Tests for the rules file: reading it, printing it, and the contradictions
// it is checked for before anything acts on it. The helpers shared with the
// file beside this one live here.

package diagnose

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

// TestMain loads the rules parser before any test moves the environment, so
// the native library it keeps open is not cached under a temporary directory.
//
// TestMain also makes the synthetic world's promise for the whole binary: the
// sandbox SIDs these tests grant with are made up, so the operations they
// drive must treat them as identifiers that stand alone rather than as
// groups that have to exist (the fail-closed half of that contract is
// measured in the acl package, which never turns this on).
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
	restore := grant.IdentitiesStandAloneForTest()
	code := m.Run()
	restore()
	os.Exit(code)
}

func useRules(t *testing.T, rules *config.Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.ktav")
	t.Setenv(config.EnvPath, path)
	if rules != nil {
		if err := rules.Save(); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestConfigNeedsAnAction(t *testing.T) {
	err := Config(nil)
	if got := exit.Of(err); got != exit.Usage {
		t.Errorf("exit code is %v, want %v", got, exit.Usage)
	}
	if got := exit.Of(Config([]string{"frobnicate"})); got != exit.Usage {
		t.Errorf("an unknown action gave %v", got)
	}
}

func TestConfigPathAndShowSucceed(t *testing.T) {
	useRules(t, &config.Config{Projects: []config.Rule{{Dir: `C:\app`, RW: []string{`C:\tools`}}}})
	if err := Config([]string{"path"}); err != nil {
		t.Errorf("path: %v", err)
	}
	if err := Config([]string{"show"}); err != nil {
		t.Errorf("show: %v", err)
	}
	if err := Config([]string{"show", "--json"}); err != nil {
		t.Errorf("show --json: %v", err)
	}
}

func TestConfigShowReportsAProjectWithoutRules(t *testing.T) {
	useRules(t, &config.Config{})
	err := Config([]string{"show", "--dir", t.TempDir()})
	if got := exit.Of(err); got != exit.NotFound {
		t.Errorf("exit code is %v, want %v", got, exit.NotFound)
	}
}

func TestValidateAcceptsAFileInOrder(t *testing.T) {
	tools := t.TempDir()
	useRules(t, &config.Config{Projects: []config.Rule{{Dir: t.TempDir(), RW: []string{tools}}}})
	if err := Config([]string{"validate"}); err != nil {
		t.Errorf("a sound file was rejected: %v", err)
	}
}

// TestValidateFindsADirectoryInBothLists is the check that matters most: such
// a file quietly costs write access, because the readable entry is applied
// last.
func TestValidateFindsADirectoryInBothLists(t *testing.T) {
	tools := t.TempDir()
	useRules(t, &config.Config{Projects: []config.Rule{{
		Dir: t.TempDir(), RW: []string{tools}, RO: []string{tools},
	}}})
	err := Config([]string{"validate"})
	if got := exit.Of(err); got != exit.BadConfig {
		t.Errorf("exit code is %v, want %v", got, exit.BadConfig)
	}
	complaints := inspectRules(&config.Config{Projects: []config.Rule{{
		Dir: `C:\app`, RW: []string{tools}, RO: []string{tools},
	}}})
	var found bool
	for _, complaint := range complaints {
		if complaint.Kind == "conflict" {
			found = true
			if !strings.Contains(complaint.Message, "write access would be lost") {
				t.Errorf("unhelpful message: %s", complaint.Message)
			}
		}
	}
	if !found {
		t.Errorf("the clash was not reported as a conflict: %+v", complaints)
	}
}

func TestValidateFindsADuplicate(t *testing.T) {
	tools := t.TempDir()
	complaints := inspectRules(&config.Config{Projects: []config.Rule{{
		Dir: `C:\app`, RW: []string{tools, strings.ToLower(tools)},
	}}})
	if len(complaints) != 1 || complaints[0].Kind != "duplicate" {
		t.Errorf("got %+v", complaints)
	}
}

// TestValidateSeparatesAMissingDirectoryFromAMistake covers the rule that a
// directory which has since been removed is worth mentioning but is not an
// error in the file.
func TestValidateSeparatesAMissingDirectoryFromAMistake(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "removed")
	useRules(t, &config.Config{Projects: []config.Rule{{Dir: t.TempDir(), RW: []string{gone}}}})
	if err := Config([]string{"validate"}); err != nil {
		t.Errorf("a missing directory should not fail the check: %v", err)
	}
	complaints := inspectRules(&config.Config{Projects: []config.Rule{{
		Dir: `C:\app`, RW: []string{gone},
	}}})
	if len(complaints) != 1 || complaints[0].Kind != "missing" {
		t.Errorf("got %+v", complaints)
	}
}

func TestValidateReportsABrokenFile(t *testing.T) {
	path := useRules(t, nil)
	if err := os.WriteFile(path, []byte("projects: [ { dir: "), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Config([]string{"validate"})
	if got := exit.Of(err); got != exit.BadConfig {
		t.Errorf("exit code is %v, want %v", got, exit.BadConfig)
	}
}

// TestValidateFindsAConflictSpreadOverTwoRules is the regression guard for a
// file that looked sound and was not: the checks were scoped to a single rule,
// so the same directory asked for twice, in two rules for the same project,
// went unnoticed. Only the first rule is applied, so the second was silently
// dropped.
func TestValidateFindsAConflictSpreadOverTwoRules(t *testing.T) {
	project, tools := t.TempDir(), t.TempDir()
	useRules(t, &config.Config{Projects: []config.Rule{
		{Dir: project, RW: []string{tools}},
		{Dir: project, RO: []string{tools}},
	}})
	err := Config([]string{"validate"})
	if got := exit.Of(err); got != exit.BadConfig {
		t.Errorf("exit code is %v, want %v", got, exit.BadConfig)
	}
	complaints := inspectRules(&config.Config{Projects: []config.Rule{
		{Dir: project, RW: []string{tools}},
		{Dir: project, RO: []string{tools}},
	}})
	var sawProject, sawPath bool
	for _, complaint := range complaints {
		if complaint.Kind == "duplicate" && strings.Contains(complaint.Message, "more than one rule") {
			sawProject = true
		}
		if complaint.Kind == "conflict" {
			sawPath = true
		}
	}
	if !sawProject {
		t.Errorf("the repeated project was not reported: %+v", complaints)
	}
	if !sawPath {
		t.Errorf("the directory asked for both ways was not reported: %+v", complaints)
	}
}

func TestValidateAcceptsTheSameDirectoryInDifferentProjects(t *testing.T) {
	shared := t.TempDir()
	useRules(t, &config.Config{Projects: []config.Rule{
		{Dir: t.TempDir(), RW: []string{shared}},
		{Dir: t.TempDir(), RO: []string{shared}},
	}})
	if err := Config([]string{"validate"}); err != nil {
		t.Errorf("two projects may each name the same directory: %v", err)
	}
}

// TestValidateScopedToAProjectIgnoresAnotherOne is the regression guard for a
// check that read the flag and then threw it away: asking about a sound
// project failed because a different project in the same file had a mistake.
func TestValidateScopedToAProjectIgnoresAnotherOne(t *testing.T) {
	sound, broken, tools := t.TempDir(), t.TempDir(), t.TempDir()
	useRules(t, &config.Config{Projects: []config.Rule{
		{Dir: sound, RW: []string{tools}},
		{Dir: broken, RW: []string{tools}, RO: []string{tools}},
	}})
	if err := Config([]string{"validate", "--dir", sound}); err != nil {
		t.Errorf("checking a project in order failed over another project's mistake: %v", err)
	}
	err := Config([]string{"validate", "--dir", broken})
	if got := exit.Of(err); got != exit.BadConfig {
		t.Errorf("the broken project passed: exit code %v, want %v", got, exit.BadConfig)
	}
	if err := Config([]string{"validate"}); exit.Of(err) != exit.BadConfig {
		t.Error("the whole file should still fail when any project is broken")
	}
}

// TestValidateScopedToAProjectWithoutARuleSaysSo keeps the flag meaning the
// same thing in both actions: show reports a project with no rule rather than
// printing nothing, and a check that silently passed would be worse.
func TestValidateScopedToAProjectWithoutARuleSaysSo(t *testing.T) {
	useRules(t, &config.Config{Projects: []config.Rule{{Dir: t.TempDir()}}})
	err := Config([]string{"validate", "--dir", t.TempDir()})
	if got := exit.Of(err); got != exit.NotFound {
		t.Errorf("exit code is %v, want %v", got, exit.NotFound)
	}
}

// TestValidateScopedToAProjectStillFindsARepeatedRule covers why the whole
// file is inspected before the answer is narrowed: a second rule for the same
// project is invisible to anything that only looks at the first.
func TestValidateScopedToAProjectStillFindsARepeatedRule(t *testing.T) {
	project, tools := t.TempDir(), t.TempDir()
	useRules(t, &config.Config{Projects: []config.Rule{
		{Dir: project, RW: []string{tools}},
		{Dir: project, RW: []string{tools}},
	}})
	err := Config([]string{"validate", "--dir", project})
	if got := exit.Of(err); got != exit.BadConfig {
		t.Errorf("exit code is %v, want %v", got, exit.BadConfig)
	}
}

func TestSplitKeepsOptionValuesTogether(t *testing.T) {
	options, operands := split([]string{`C:\path`, "--operation", "write", "--json", "--dir", `C:\p`})
	if len(operands) != 1 || operands[0] != `C:\path` {
		t.Errorf("operands are %v", operands)
	}
	want := []string{"--operation", "write", "--json", "--dir", `C:\p`}
	if strings.Join(options, " ") != strings.Join(want, " ") {
		t.Errorf("options are %v, want %v", options, want)
	}
}

// TestTheHelpListsExactlyTheFlagsDiagnoseTakes holds explain, check and config
// to their entries, for the reason the others are held to theirs: the options
// in the help are written by hand and nothing else keeps them true.
func TestTheHelpListsExactlyTheFlagsDiagnoseTakes(t *testing.T) {
	explain, _ := explainFlags()
	ask, _ := checkFlags()
	rules, _ := configFlags("show")
	for command, flags := range map[string]*flag.FlagSet{
		"explain": explain, "check": ask, "config": rules,
	} {
		undocumented, missing := usage.Mismatch(command, flags)
		if len(undocumented) > 0 {
			t.Errorf("%s takes %v, which its help never mentions", command, undocumented)
		}
		if len(missing) > 0 {
			t.Errorf("the help offers %v on %s, which it would reject", missing, command)
		}
	}
}
