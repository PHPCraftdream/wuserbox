package diagnose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/exit"
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

func TestCheckNeedsAPathAndAKnownOperation(t *testing.T) {
	if got := exit.Of(Check(nil)); got != exit.Usage {
		t.Errorf("a missing path gave %v", got)
	}
	if got := exit.Of(Check([]string{t.TempDir(), "--operation", "rename"})); got != exit.Usage {
		t.Errorf("an unknown operation gave %v", got)
	}
}

func TestCheckReportsAnUninitializedSandbox(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	err := Check([]string{t.TempDir(), "--dir", t.TempDir()})
	if got := exit.Of(err); got != exit.NotFound {
		t.Errorf("exit code is %v, want %v", got, exit.NotFound)
	}
}

func TestExplainReportsAnUninitializedSandbox(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	err := Explain([]string{"--dir", t.TempDir()})
	if got := exit.Of(err); got != exit.NotFound {
		t.Errorf("exit code is %v, want %v", got, exit.NotFound)
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

func TestReportKindsAreTheOnesGrantUses(t *testing.T) {
	// The report prints the kind straight from the record, so the two have to
	// agree on spelling.
	for _, kind := range []grant.Kind{grant.RW, grant.RO, grant.File, grant.HomeTop} {
		if string(kind) == "" {
			t.Errorf("a grant kind has no name")
		}
	}
}
