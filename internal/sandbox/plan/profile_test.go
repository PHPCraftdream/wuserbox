package plan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/profile"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/facts"
)

// TestAddProfilePreviewReportsWhatFillingTheProfileWouldDo is the guard for
// the whole of --dry-run's profile section: without AddProfilePreview wired
// in, a preview says nothing about cleanup or copying at all, however rich
// the rules file's profile: and cleanup: sections are. It also pins the
// promise the doc makes: nothing is written or deleted by asking.
func TestAddProfilePreviewReportsWhatFillingTheProfileWouldDo(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))

	if err := os.WriteFile(filepath.Join(home, "credentials.json"), []byte(`{"token":"abc"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rules := &config.Config{
		Profile: config.Entries([]string{"credentials.json"}),
		Cleanup: config.Masks([]string{"*.log"}),
	}
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}

	const group = "wub-preview-test-00000000"
	profileDir := sandbox.ProfileDir(group)
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "stale.log"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &Plan{Group: group}
	if err := p.AddProfilePreview(group, false); err != nil {
		t.Fatal(err)
	}

	if len(p.Cleanup) != 1 || p.Cleanup[0].Path != "stale.log" || p.Cleanup[0].Files != 1 {
		t.Errorf("cleanup preview is %+v, want one match for stale.log holding one file", p.Cleanup)
	}
	if _, err := os.Stat(filepath.Join(profileDir, "stale.log")); err != nil {
		t.Errorf("a preview deleted what it was only supposed to report: %v", err)
	}

	if len(p.Profile) != 1 || p.Profile[0].Path != "credentials.json" ||
		p.Profile[0].Files != 1 || p.Profile[0].Bytes != int64(len(`{"token":"abc"}`)) {
		t.Errorf("profile preview is %+v, want one file for credentials.json", p.Profile)
	}
	if _, err := os.Stat(filepath.Join(profileDir, "credentials.json")); !os.IsNotExist(err) {
		t.Errorf("a preview copied what it was only supposed to report: %v", err)
	}

	// --no-ai turns this whole section off, mirroring fillProfile's own
	// branch in internal/cli/setup/run.go: a sandbox told to skip the
	// preset never has its profile: entries copied, only cleared, so there
	// is nothing to preview here either.
	skipped := &Plan{Group: group}
	if err := skipped.AddProfilePreview(group, true); err != nil {
		t.Fatal(err)
	}
	if skipped.Cleanup != nil || skipped.Profile != nil {
		t.Errorf("--no-ai should leave the preview empty, got cleanup=%v profile=%v", skipped.Cleanup, skipped.Profile)
	}

	// A file a real run already copied, unchanged since, is skipped rather
	// than counted as something the next run would copy again -- the same
	// fingerprint comparison mirror.go's copySink makes, asked read-only.
	copied, newPrints, err := profile.Copy(profileDir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := facts.RecordCopied(group, copied); err != nil {
		t.Fatal(err)
	}
	if err := facts.RecordPrints(group, newPrints); err != nil {
		t.Fatal(err)
	}

	again := &Plan{Group: group}
	if err := again.AddProfilePreview(group, false); err != nil {
		t.Fatal(err)
	}
	if len(again.Profile) != 1 || again.Profile[0].Files != 0 || again.Profile[0].Skipped != 1 {
		t.Errorf("profile preview after an unchanged real copy is %+v, want the file skipped rather than copied again",
			again.Profile)
	}
}
