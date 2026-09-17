package profile

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// useProfile points the config package and paths.Home at fresh temporary
// directories and writes a rules file whose profile section is entries, the
// way a hand-edited or pre-filled rules file would.
func useProfile(t *testing.T, entries []string) (home, dest string) {
	t.Helper()
	home = t.TempDir()
	dest = filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	if err := (&config.Config{Profile: config.Entries(entries)}).Save(); err != nil {
		t.Fatal(err)
	}
	return home, dest
}

// useProfileEntries is useProfile's twin for a test that needs an entry
// carrying depth, include or exclude -- config.Entries only wraps bare
// paths, and a duplicate that differs only in its limits cannot be written
// that way.
func useProfileEntries(t *testing.T, entries []config.Entry) (home, dest string) {
	t.Helper()
	home = t.TempDir()
	dest = filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	if err := (&config.Config{Profile: entries}).Save(); err != nil {
		t.Fatal(err)
	}
	return home, dest
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// lastCopied remembers what the previous Copy reported for a destination.
// Threading that list into the next call is the caller's job in a real run --
// it is how Copy knows what to clear, and it deliberately lives outside the
// profile, where the sandbox cannot edit it into an instruction to delete
// something else. A test that passed nil every time would be testing
// something no run does.
//
// lastPrints does the same for the fingerprints, kept by the caller for the
// same reason.
var lastCopied = map[string][]config.Entry{}
var lastPrints = map[string]map[string]Print{}

func fill(t *testing.T, dest string) []config.Entry {
	t.Helper()
	copied, prints, err := Copy(dest, lastCopied[dest], lastPrints[dest])
	if err != nil {
		t.Fatal(err)
	}
	lastCopied[dest] = copied
	lastPrints[dest] = prints
	return copied
}

// pathsOf is the entries' own paths, for tests that care what was copied
// rather than the entries whole.
func pathsOf(entries []config.Entry) []string {
	paths := make([]string, len(entries))
	for i, entry := range entries {
		paths[i] = entry.Path
	}
	return paths
}

func junctionTo(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("this machine would not make a junction: %v %s", err, out)
	}
}
