package grants

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

func TestResetProfileBacksUpWholeRulesAndKeepsOtherSettings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	path := filepath.Join(t.TempDir(), "rules.ktav")
	t.Setenv(config.EnvPath, path)
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "auth.json"), []byte("test credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := &config.Config{
		Projects: []config.Rule{{Dir: `C:\project`, RW: []string{`C:\shared`}}},
		Profile:  config.Entries([]string{"my-setting"}),
		Cleanup:  config.Masks([]string{"cache/**"}),
	}
	if err := want.Save(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := ResetProfile()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(backup, path+".backup-") {
		t.Fatalf("backup path %q does not belong to the rules file", backup)
	}
	saved, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved, before) {
		t.Fatal("backup does not hold the exact previous rules")
	}
	if protected, err := acl.IsProtected(backup); err != nil || !protected {
		t.Fatalf("backup is not protected: protected=%v err=%v", protected, err)
	}
	after, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Profile) != 1 || after.Profile[0].Path != ".codex/auth.json" {
		t.Errorf("defaults were not restored for the installed agent: %+v", after.Profile)
	}
	if len(after.Projects) != 1 || !config.SamePath(after.Projects[0].Dir, `C:\project`) ||
		len(after.Projects[0].RW) != 1 || !config.SamePath(after.Projects[0].RW[0], `C:\shared`) {
		t.Errorf("project grants changed: %+v", after.Projects)
	}
	if len(after.Cleanup) != 1 || after.Cleanup[0].Pattern != "cache/**" {
		t.Errorf("cleanup rules changed: %+v", after.Cleanup)
	}
	otherBackup, err := ResetProfile()
	if err != nil {
		t.Fatal(err)
	}
	if otherBackup == backup {
		t.Fatal("a second reset overwrote the first backup")
	}
	if saved, err := os.ReadFile(backup); err != nil || !bytes.Equal(saved, before) {
		t.Fatalf("the first backup changed on a second reset: %v", err)
	}
}

func TestResetProfileFirstUseCreatesDefaultsWithoutBackup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	path := filepath.Join(t.TempDir(), "rules.ktav")
	t.Setenv(config.EnvPath, path)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	backup, err := ResetProfile()
	if err != nil || backup != "" {
		t.Fatalf("first reset returned backup=%q err=%v", backup, err)
	}
	rules, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.Profile) != 1 || rules.Profile[0].Path != ".claude.json" {
		t.Errorf("first reset did not create defaults: %+v", rules.Profile)
	}
}

func TestResetProfileDoesNotReplaceUnreadableRules(t *testing.T) {
	t.Setenv("USERPROFILE", t.TempDir())
	path := filepath.Join(t.TempDir(), "rules.ktav")
	t.Setenv(config.EnvPath, path)
	broken := []byte("profile: [")
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResetProfile(); err == nil {
		t.Fatal("malformed rules were replaced, losing project grants")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, broken) {
		t.Fatalf("malformed rules changed: %v", err)
	}
	if backups, _ := filepath.Glob(path + ".backup-*"); len(backups) != 0 {
		t.Errorf("a backup appeared even though nothing was changed: %v", backups)
	}
}
