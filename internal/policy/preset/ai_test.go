package preset

import (
	"os"
	"path/filepath"
	"testing"

	"wuserbox/internal/policy/grant"
)

func TestAIListsOnlyExistingPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))

	claude := filepath.Join(home, ".claude")
	if err := os.Mkdir(claude, 0o755); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(configFile, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	specs := AI()
	byPath := map[string]grant.Kind{}
	for _, s := range specs {
		byPath[s.Path] = s.Kind
	}
	if byPath[claude] != grant.RW {
		t.Errorf("existing agent directory was not granted: %v", specs)
	}
	if byPath[configFile] != grant.File {
		t.Errorf("existing agent config file was not granted: %v", specs)
	}
	if byPath[filepath.Join(home, ".codex")] != "" {
		t.Error("a directory that does not exist was granted")
	}
	if _, listed := byPath[home]; listed {
		t.Error("the profile root must not be handed over by default")
	}
}
