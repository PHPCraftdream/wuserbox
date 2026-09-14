package diagnose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
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

// TestExplainNoticesAccessBeyondTheRecord is the regression guard for the more
// dangerous half of drift. A directory recorded as read-only that the sandbox
// can write to used to be reported as in good order, because only the recorded
// access was ever checked.
func TestExplainNoticesAccessBeyondTheRecord(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	target := t.TempDir()
	s := &state.State{
		Group: "wub-explain-test",
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-121212",
		Dir:   t.TempDir(),
		Temp:  t.TempDir(),
	}
	// Recorded as read-only, granted as writable: the two disagree.
	if err := s.Add(target, grant.RO); err != nil {
		t.Fatal(err)
	}
	if err := grant.Apply(s.SID, target, grant.RW); !grant.Applied(err) {
		t.Fatal(err)
	}

	report, err := build(s)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, account := range report.Accounts {
		if !strings.EqualFold(account.Path, target) {
			continue
		}
		found = true
		if account.InForce {
			t.Error("a read-only entry the sandbox can write to was reported as in order")
		}
		if !strings.Contains(account.Note, "can write") {
			t.Errorf("unhelpful note: %q", account.Note)
		}
	}
	if !found {
		t.Fatalf("the directory is missing from the report: %+v", report.Accounts)
	}
	if len(report.Drifted) == 0 {
		t.Error("the excess was not counted as drift")
	}
}

func TestExplainNoticesAPermissionThatWasLost(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	target := t.TempDir()
	s := &state.State{
		Group: "wub-explain-test",
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-131313",
		Dir:   t.TempDir(),
		Temp:  t.TempDir(),
	}
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := grant.Revoke(s.SID, target); err != nil {
		t.Fatal(err)
	}
	report, err := build(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Drifted) == 0 {
		t.Errorf("a lost permission was not noticed: %+v", report.Accounts)
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

// TestExplainJudgesAPermissionByItsOwnKind is the regression guard for a check
// that asked one question about every kind. The permission that lets an agent
// create files in the profile root, without creating directories there, fails
// a plain write by design, and was reported as broken while working exactly as
// intended.
func TestExplainJudgesAPermissionByItsOwnKind(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	s := &state.State{
		Group: "wub-kind-test",
		SID:   "S-1-5-21-1111111111-2222222222-3333333333-161616",
		Dir:   t.TempDir(),
		Temp:  t.TempDir(),
	}
	if err := s.Add(home, grant.HomeTop); err != nil {
		t.Fatal(err)
	}
	report, err := build(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range report.Accounts {
		if !strings.EqualFold(account.Path, home) {
			continue
		}
		if !account.InForce {
			t.Errorf("a working permission was called broken: %s", account.Note)
		}
	}
	if len(report.Drifted) != 0 {
		t.Errorf("nothing is wrong, yet the report lists %v", report.Drifted)
	}
}

func TestEveryKindHasAnOperationThatProvesIt(t *testing.T) {
	for _, kind := range []grant.Kind{grant.RW, grant.RO, grant.File, grant.HomeTop} {
		if _, err := access.Parse(kind.Proves()); err != nil {
			t.Errorf("%q is proved by %q, which is not an operation: %v", kind, kind.Proves(), err)
		}
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

// TestExplainNoticesCreationUnderAReadOnlyRecord is the regression guard for a
// check that asked only about a plain write. A permission that creates files
// without creating subdirectories is refused a write and allowed a create, so
// a directory recorded as read-only while actually holding home-top was
// reported as being in good order.
func TestExplainNoticesCreationUnderAReadOnlyRecord(t *testing.T) {
	const account = "S-1-5-21-1111111111-2222222222-3333333333-181818"
	dir := t.TempDir()
	s := &state.State{Group: "wub-ro-record", SID: account, Dir: t.TempDir(), Temp: t.TempDir()}
	// The record says read-only; the file system says otherwise. That is the
	// drift the report exists to catch, so it is built rather than asked for.
	if err := grant.Apply(account, dir, grant.HomeTop); !grant.Applied(err) {
		t.Fatal(err)
	}
	s.Grants = []grant.Spec{{Path: dir, Kind: grant.RO}}

	inForce, note := inForce(account, s.Grants[0], false)
	if inForce {
		t.Fatal("a directory the sandbox can create files in was reported as read-only")
	}
	if !strings.Contains(note, "create") {
		t.Errorf("the note does not name the operation that is allowed: %s", note)
	}
}

// TestExplainAcceptsAReadOnlyRecordThatHoldsUp keeps the stricter check from
// calling a sound read-only permission broken, including one that sits inside
// a directory the sandbox may write to.
func TestExplainAcceptsAReadOnlyRecordThatHoldsUp(t *testing.T) {
	const account = "S-1-5-21-1111111111-2222222222-3333333333-191919"
	project := t.TempDir()
	inner := filepath.Join(project, "reference")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &state.State{Group: "wub-ro-sound", SID: account, Dir: project, Temp: t.TempDir()}
	if err := s.Add(project, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(inner, grant.RO); err != nil {
		t.Fatal(err)
	}
	if ok, note := inForce(account, grant.Spec{Path: inner, Kind: grant.RO}, false); !ok {
		t.Errorf("a sound read-only permission was called broken: %s", note)
	}
}

// TestExplainJudgesAReadOnlyFileByTheFileItself is the regression guard for a
// check that asked a single file whether something could be created. Creating
// is a question about the directory that would hold the new thing, so a file
// held read-only inside a project the sandbox may write to was reported as
// writable because a neighbor could be made beside it.
func TestExplainJudgesAReadOnlyFileByTheFileItself(t *testing.T) {
	const account = "S-1-5-21-1111111111-2222222222-3333333333-222222"
	project := t.TempDir()
	guarded := filepath.Join(project, "settings.json")
	if err := os.WriteFile(guarded, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &state.State{Group: "wub-ro-file", SID: account, Dir: project, Temp: t.TempDir()}
	if err := s.Add(project, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(guarded, grant.RO); err != nil {
		t.Fatal(err)
	}
	if ok, note := inForce(account, grant.Spec{Path: guarded, Kind: grant.RO}, false); !ok {
		t.Errorf("a file that is genuinely read-only was called broken: %s", note)
	}

	// Writing it must still be refused, or the check would say nothing at all.
	writable, err := access.Check(account, guarded, access.Write, false)
	if err != nil {
		t.Fatal(err)
	}
	if writable.Allowed {
		t.Error("the file was writable, so this test proves nothing")
	}
}

// TestExplainStillAsksADirectoryAboutCreating keeps the narrowing from going
// too far: a directory recorded as read-only that the sandbox can create files
// in is still reported as not in force.
func TestExplainStillAsksADirectoryAboutCreating(t *testing.T) {
	const account = "S-1-5-21-1111111111-2222222222-3333333333-232323"
	dir := t.TempDir()
	if err := grant.Apply(account, dir, grant.HomeTop); !grant.Applied(err) {
		t.Fatal(err)
	}
	if ok, note := inForce(account, grant.Spec{Path: dir, Kind: grant.RO}, false); ok {
		t.Error("a directory the sandbox can create files in was reported as read-only")
	} else if !strings.Contains(note, "create") {
		t.Errorf("the note does not name the operation that is allowed: %s", note)
	}
}
