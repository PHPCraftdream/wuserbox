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
	for _, entry := range missing {
		if filepath.Dir(entry.Path) != home {
			t.Errorf("%s is not in the profile root", entry.Path)
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
	for _, entry := range Missing() {
		if name := filepath.Base(entry.Path); name == ".bash_profile" || name == ".bash_login" {
			t.Errorf("%s would hide the existing .profile", entry.Path)
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

// TestMissingSaysWhichNamesAreDirectories is what keeps a reserved .ssh from
// being taken as an empty file, which would break the tools that read it.
func TestMissingSaysWhichNamesAreDirectories(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)

	kinds := map[string]bool{}
	for _, entry := range Missing() {
		kinds[filepath.Base(entry.Path)] = entry.IsDirectory
	}
	for _, name := range []string{".ssh", ".gnupg", ".aws", ".azure", ".docker", ".kube"} {
		if !kinds[name] {
			t.Errorf("%s is not marked as a directory", name)
		}
	}
	for _, name := range []string{".bashrc", ".gitconfig", ".netrc", ".wuserbox.ktav"} {
		if kinds[name] {
			t.Errorf("%s is marked as a directory", name)
		}
	}
}

// TestAIHandsOverTheConfigDirectory covers the whole of ~/.config being part
// of the preset, rather than only the agent directories inside it: tools keep
// their settings there and expect to write them.
func TestAIHandsOverTheConfigDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	config := filepath.Join(home, ".config")
	if err := os.Mkdir(config, 0o755); err != nil {
		t.Fatal(err)
	}

	byPath := map[string]grant.Kind{}
	for _, s := range AI() {
		byPath[s.Path] = s.Kind
	}
	if byPath[config] != grant.RW {
		t.Errorf("~/.config was not handed over: %v", AI())
	}
}
