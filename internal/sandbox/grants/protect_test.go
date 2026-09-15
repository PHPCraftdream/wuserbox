// Tests for the files a sandbox must never change: the rules file and the
// credentials in the profile root, the names reserved before a sandbox can
// create them itself, and the refusals that survive a permission above.

package grants

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
)

func TestProtectSettingsLocksTheRulesFile(t *testing.T) {
	s := newState(t)
	rulesPath := filepath.Join(tempDir(t), "rules.ktav")
	t.Setenv(config.EnvPath, rulesPath)
	if err := (&config.Config{}).Save(); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if err := ProtectSettings(s); err != nil {
		t.Fatal(err)
	}
	// The owner keeps full access, which is what makes the tool usable.
	if err := os.WriteFile(rulesPath, []byte("projects: []\n"), 0o644); err != nil {
		t.Errorf("the owner lost access to the rules: %v", err)
	}
}

// TestRetiringOldProfileRulesKeepsWhatSomebodyAdded is the whole risk of
// editing a file that belongs to the person using the tool.
//
// The entries an older default wrote have to go, because they copy whole
// agent state directories into every sandbox on every run and no later
// version rewrites that file. Everything else in the section was typed by
// somebody, and nothing here can tell a person who wants a whole tree copied
// from a default that wanted it on their behalf -- so only what is
// recognizable as the default's own doing is touched.
func TestRetiringOldProfileRulesKeepsWhatSomebodyAdded(t *testing.T) {
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))
	t.Setenv("USERPROFILE", tempDir(t))

	old := preset.RetiredProfileEntries()
	if len(old) == 0 {
		t.Skip("this machine resolves no profile root, so there is no old default to recognize")
	}
	const mine = "my-own-directory"
	rules := &config.Config{Profile: append([]string{mine}, old...)}
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}

	retired, err := RetireWholeDirectoryProfileRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != len(old) {
		t.Errorf("took out %d of the %d entries the old default wrote", len(retired), len(old))
	}
	after, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	kept := false
	for _, entry := range after.Profile {
		if entry == mine {
			kept = true
		}
		for _, gone := range old {
			if entry == gone {
				t.Errorf("%q is still listed, so a whole directory is still copied on every run", entry)
			}
		}
	}
	if !kept {
		t.Errorf("%q was taken out, and nobody but the person using this put it there", mine)
	}

	// And again changes nothing: a run that rewrote the file every time would
	// fight anybody editing it.
	again, err := RetireWholeDirectoryProfileRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Errorf("a second pass took out %d more entries", len(again))
	}
}

func TestProtectSettingsCreatesTheRulesFile(t *testing.T) {
	// A sandbox that may create files in the profile root must not be able to
	// write the rules file first: it would grant itself directories on the
	// next ordinary run.
	rulesPath := filepath.Join(tempDir(t), "rules.ktav")
	t.Setenv(config.EnvPath, rulesPath)
	t.Setenv("USERPROFILE", tempDir(t))
	s := newState(t)

	if _, err := os.Stat(rulesPath); err == nil {
		t.Fatal("the rules file exists before the test starts")
	}
	if err := ProtectSettings(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rulesPath); err != nil {
		t.Fatalf("the rules file was not created: %v", err)
	}
	rules, err := config.Load()
	if err != nil {
		t.Fatalf("the created rules file does not parse: %v", err)
	}
	if len(rules.Projects) != 0 {
		t.Errorf("the created rules file is not empty: %+v", rules.Projects)
	}
}

func TestRefuseHomeFilesLeavesGrantedFilesAlone(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	s := newState(t)

	granted := filepath.Join(home, ".agent.json")
	companion := filepath.Join(home, ".agent.json.tmp.1234")
	other := filepath.Join(home, ".bashrc")
	for _, f := range []string{granted, companion, other} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Add(granted, grant.File); err != nil {
		t.Fatal(err)
	}
	if err := RefuseHomeFiles(s); err != nil {
		t.Fatal(err)
	}
	// Nothing is recorded as a grant; refusals are applied directly.
	if len(s.Grants) != 1 {
		t.Errorf("refusals leaked into the record: %+v", s.Grants)
	}
}

func TestIsAllowedMatchesCompanionFiles(t *testing.T) {
	allowed := []string{`C:\Users\me\.agent.json`}
	cases := map[string]bool{
		`C:\Users\me\.agent.json`:          true,
		`C:\USERS\ME\.AGENT.JSON`:          true,
		`C:\Users\me\.agent.json.tmp.9182`: true,
		`C:\Users\me\.agent.jsonx`:         false,
		`C:\Users\me\.bashrc`:              false,
	}
	for path, want := range cases {
		if got := isAllowed(path, allowed); got != want {
			t.Errorf("isAllowed(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestReserveSensitiveNamesTakesTheNamesFirst(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))

	unguarded, err := ReserveSensitiveNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(unguarded) != 0 {
		t.Errorf("nothing should be unreachable in an empty profile: %v", unguarded)
	}
	for _, name := range []string{".bashrc", ".gitconfig", ".netrc", ".bash_profile"} {
		if _, err := os.Stat(filepath.Join(home, name)); err != nil {
			t.Errorf("%s was not reserved: %v", name, err)
		}
	}
}

func TestReserveSensitiveNamesKeepsExistingContent(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	existing := filepath.Join(home, ".gitconfig")
	if err := os.WriteFile(existing, []byte("[user]\n\tname = someone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveSensitiveNames(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(existing)
	if err != nil || !strings.Contains(string(data), "someone") {
		t.Errorf("an existing file was overwritten: %q (%v)", data, err)
	}
}

func TestReserveSensitiveNamesReportsWhatItCannotTake(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	if err := os.WriteFile(filepath.Join(home, ".profile"), []byte("export X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unguarded, err := ReserveSensitiveNames()
	if err != nil {
		t.Fatal(err)
	}
	var reported bool
	for _, path := range unguarded {
		if filepath.Base(path) == ".bash_profile" {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the caller was not told about .bash_profile: %v", unguarded)
	}
	if _, err := os.Stat(filepath.Join(home, ".bash_profile")); err == nil {
		t.Error(".bash_profile was created and now hides the real .profile")
	}
}

// TestReserveSensitiveNamesKeepsDirectoriesDirectories is the regression guard
// for a fix that was worse than the problem: taking .ssh as an empty file
// would break every tool that expects a directory there, inside the sandbox
// and outside it.
func TestReserveSensitiveNamesKeepsDirectoriesDirectories(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))

	if _, err := ReserveSensitiveNames(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".ssh", ".gnupg", ".aws", ".azure", ".docker", ".kube"} {
		info, err := os.Stat(filepath.Join(home, name))
		if err != nil {
			t.Errorf("%s was not reserved: %v", name, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s was taken as a file; a tool expecting a directory would break", name)
		}
	}
	for _, name := range []string{".bashrc", ".gitconfig", ".netrc"} {
		info, err := os.Stat(filepath.Join(home, name))
		if err != nil {
			t.Errorf("%s was not reserved: %v", name, err)
			continue
		}
		if info.IsDir() {
			t.Errorf("%s was taken as a directory", name)
		}
	}
}

func TestReserveSensitiveNamesLeavesAnExistingDirectoryAlone(t *testing.T) {
	home := tempDir(t)
	t.Setenv("USERPROFILE", home)
	keys := filepath.Join(home, ".ssh")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "id_ed25519"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveSensitiveNames(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(keys, "id_ed25519")); err != nil {
		t.Errorf("an existing key was lost: %v", err)
	}
}
