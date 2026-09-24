package access

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

func TestAddDirFirstUseKeepsDefaultProfileCopies(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "auth.json"), []byte("test credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	project, shared := t.TempDir(), t.TempDir()
	if err := AddDir([]string{shared, "--dir", project}); err != nil {
		t.Fatal(err)
	}
	rules, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.Profile) != 1 || rules.Profile[0].Path != ".codex/auth.json" {
		t.Errorf("first add-dir created rules without the installed agent's credentials: %+v", rules.Profile)
	}
	if len(rules.Projects) != 1 || len(rules.Projects[0].RW) != 1 {
		t.Errorf("directory grant was lost: %+v", rules.Projects)
	}
}
