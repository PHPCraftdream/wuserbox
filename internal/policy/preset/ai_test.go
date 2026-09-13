package preset

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
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

func TestMissingListsNamesThatCanBeReserved(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)

	missing := Missing()
	if len(missing) == 0 {
		t.Fatal("an empty profile root should offer names to reserve")
	}
	for _, path := range missing {
		if filepath.Dir(path) != home {
			t.Errorf("%s is not in the profile root", path)
		}
	}
	// With nothing in place yet, every startup file is safe to reserve.
	if len(Shadowable()) != 0 {
		t.Errorf("nothing should be unreachable in an empty profile: %v", Shadowable())
	}
}

func TestMissingLeavesAStartupFileThatWouldHideAnother(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	// The shell reads .bash_profile first and stops, so creating it would
	// hide the .profile that is really there.
	if err := os.WriteFile(filepath.Join(home, ".profile"), []byte("export X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range Missing() {
		if filepath.Base(path) == ".bash_profile" || filepath.Base(path) == ".bash_login" {
			t.Errorf("%s would hide the existing .profile", path)
		}
	}
	var reported bool
	for _, path := range Shadowable() {
		if filepath.Base(path) == ".bash_profile" {
			reported = true
		}
	}
	if !reported {
		t.Error(".bash_profile should be reported as impossible to reserve")
	}
}

func TestSensitiveListsOnlyWhatExists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	if len(Sensitive()) != 0 {
		t.Fatalf("an empty profile root has nothing to protect: %v", Sensitive())
	}
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[user]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	found := Sensitive()
	if len(found) != 1 || filepath.Base(found[0]) != ".gitconfig" {
		t.Errorf("got %v", found)
	}
}
