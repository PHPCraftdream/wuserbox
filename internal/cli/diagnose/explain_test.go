// Tests for the two questions about access: whether one operation would be
// allowed, and whether what a sandbox actually holds still matches what its
// record says it was given.

package diagnose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
)

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

func TestReportKindsAreTheOnesGrantUses(t *testing.T) {
	// The report prints the kind straight from the record, so the two have to
	// agree on spelling.
	for _, kind := range []grant.Kind{grant.RW, grant.RO, grant.File, grant.HomeTop} {
		if string(kind) == "" {
			t.Errorf("a grant kind has no name")
		}
	}
}

func TestEveryKindHasAnOperationThatProvesIt(t *testing.T) {
	for _, kind := range []grant.Kind{grant.RW, grant.RO, grant.File, grant.HomeTop} {
		if _, err := access.Parse(kind.Proves()); err != nil {
			t.Errorf("%q is proved by %q, which is not an operation: %v", kind, kind.Proves(), err)
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
	if err := grant.Apply(s.SID, target, grant.RW, nil); err != nil {
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
	if err := grant.Revoke(s.SID, target, nil); err != nil {
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

// asking opens a token for a sandbox that is a group and nothing else, which
// is what every sandbox in this file is: a made-up identifier no account is a
// member of, so the token is a restricted copy of the caller's own and needs
// no administrator rights to build.
func asking(t *testing.T, group string) *access.Asking {
	t.Helper()
	a, err := access.Ask(access.Sandbox{Group: group})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
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
	if err := grant.Apply(account, dir, grant.HomeTop, nil); err != nil {
		t.Fatal(err)
	}
	s.Grants = []grant.Spec{{Path: dir, Kind: grant.RO}}

	inForce, note := inForce(asking(t, account), s.Grants[0])
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
	if ok, note := inForce(asking(t, account), grant.Spec{Path: inner, Kind: grant.RO}); !ok {
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
	if ok, note := inForce(asking(t, account), grant.Spec{Path: guarded, Kind: grant.RO}); !ok {
		t.Errorf("a file that is genuinely read-only was called broken: %s", note)
	}

	// Writing it must still be refused, or the check would say nothing at all.
	writable, err := access.Check(access.Sandbox{Group: account}, guarded, access.Write)
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
	if err := grant.Apply(account, dir, grant.HomeTop, nil); err != nil {
		t.Fatal(err)
	}
	if ok, note := inForce(asking(t, account), grant.Spec{Path: dir, Kind: grant.RO}); ok {
		t.Error("a directory the sandbox can create files in was reported as read-only")
	} else if !strings.Contains(note, "create") {
		t.Errorf("the note does not name the operation that is allowed: %s", note)
	}
}
