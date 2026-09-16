package preset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

func TestProfileListsTheCredentialFilesThatExist(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)

	place(t, filepath.Join(home, ".claude", ".credentials.json"), "{}")

	listed := Profile()
	entries := map[string]bool{}
	for _, entry := range listed {
		entries[entry.Path] = true
	}
	if !entries[".claude/.credentials.json"] {
		t.Errorf("an existing credential file was left out: %v", pathsOf(listed))
	}
	if entries[".codex/auth.json"] {
		t.Errorf("a credential file that does not exist was listed: %v", pathsOf(listed))
	}
}

// TestTheDefaultCannotReintroduceTheWholeDirectoryDefault is the guard on
// what the default costs. It was once the agent state directories whole,
// which measured 72,320 files and 19,436 MB copied into every sandbox on
// every run -- transcripts, logs and SQLite databases, almost no
// credentials. Naming directories is the point of the format now, so the
// old rule -- the default names no trees -- has narrowed rather than gone:
// the directories it names are the small ones it was measured against, and
// a bare entry naming one of the whole agent directories is still the
// disaster shape. This is the test a future edit meets if it tries.
func TestTheDefaultCannotReintroduceTheWholeDirectoryDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))

	// Every entry made to exist, so the whole table comes back and the
	// guard holds all of it -- an empty default would pass whatever it
	// did or did not carry.
	for _, entry := range defaultProfile {
		place(t, filepath.Join(home, filepath.FromSlash(entry.Path)), "x")
	}
	listed := Profile()
	if len(listed) != len(defaultProfile) {
		t.Fatalf("the default came back as %d of %d entries, so this guards only part of it: %v",
			len(listed), len(defaultProfile), pathsOf(listed))
	}

	retired := map[string]bool{}
	for _, path := range RetiredProfileEntries() {
		retired[strings.ToLower(filepath.ToSlash(path))] = true
	}
	for _, entry := range listed {
		// Bare entries only. An entry carrying limits says something the
		// old default could not, which makes it somebody's wording rather
		// than the disaster's ghost.
		if entry.Bare() && retired[strings.ToLower(filepath.ToSlash(entry.Path))] {
			t.Errorf("%q is listed bare, and it is one of the whole agent directories that measured 72,320 files and 19,436 MB a run", entry.Path)
		}
	}
}

// TestTheDefaultTableStaysOffTheSensitiveNames is the static half of the
// sensitive guard. The runtime test below refuses only what exists on the
// machine running it, so a sensitive name added to the table would pass
// everywhere the name does not exist yet, and ship on the first machine
// where it does. This one reads the table as written, existence aside.
func TestTheDefaultTableStaysOffTheSensitiveNames(t *testing.T) {
	guarded := map[string]bool{}
	for _, entry := range sensitive {
		guarded[strings.ToLower(entry.name)] = true
	}
	for _, entry := range defaultProfile {
		// The first segment, not the whole entry, the way the filter
		// checks it: a file named inside a protected directory is
		// protected along with it.
		if guarded[strings.ToLower(firstSegment(entry.Path))] {
			t.Errorf("the default names %s, which the tool protects from sandboxes", entry.Path)
		}
	}
}

// TestTheDefaultListCopiesNothingSensitive is the guard on a default that
// would have quietly undone a property the tool already has.
//
// wuserbox protects ~/.ssh, ~/.netrc, ~/.npmrc, ~/.gitconfig and their
// neighbors from sandboxes, so that handing over a home directory does not
// hand over the keys in it. A default list that copied any of them into every
// sandbox's profile would reverse that for everybody at once, on a first run
// nobody was watching, and it would look like a convenience while doing it.
// Adding one by hand stays possible: that is somebody choosing, which is the
// whole difference.
func TestTheDefaultListCopiesNothingSensitive(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))

	// Made to exist, so that a list which would pick them up does pick them up
	// here. The names come from the table the tool itself protects, rather than
	// from a copy written out again, so a name added there is guarded the day
	// it is added.
	guarded := map[string]bool{}
	for _, entry := range sensitive {
		path := filepath.Join(home, entry.name)
		var err error
		if entry.isDirectory {
			err = os.MkdirAll(path, 0o755)
		} else {
			err = os.WriteFile(path, []byte("secret"), 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
		guarded[strings.ToLower(entry.name)] = true
	}
	place(t, filepath.Join(home, ".claude", ".credentials.json"), "{}")

	listed := Profile()
	if len(listed) == 0 {
		t.Fatal("the default list is empty here, so it would pass whatever it held")
	}
	for _, entry := range listed {
		// The first segment, not the whole entry: a file named inside a
		// protected directory is protected along with it, so ".ssh/config"
		// has to be refused by ".ssh" being on the table.
		if guarded[strings.ToLower(firstSegment(entry.Path))] {
			t.Errorf("the default list copies %s, which the tool protects from sandboxes", entry.Path)
		}
	}
}

// And the refusal really is by directory, not only by exact name: a file
// under a protected directory must be left out even where somebody adds it
// to the candidate list by hand.
func TestTheDefaultListRefusesAFileInsideAProtectedDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	for _, entry := range sensitive {
		if !entry.isDirectory {
			continue
		}
		candidate := entry.name + "/config"
		place(t, filepath.Join(home, filepath.FromSlash(candidate)), "secret")
		original := defaultProfile
		defaultProfile = append(append([]config.Entry{}, original...), config.Entry{Path: candidate})
		listed := Profile()
		defaultProfile = original
		for _, got := range listed {
			if got.Path == candidate {
				t.Errorf("%s was listed, and %s is protected", candidate, entry.name)
			}
		}
	}
}

// TestThePluginsEntryExcludesTheMarketplaces holds the one exclusion the
// default's arithmetic depends on: `.claude/plugins` measured 44 MB, of
// which almost all -- 1,139 files -- was `marketplaces`, a cache of other
// people's plugin repositories. Without the exclusion the entry is the old
// disaster in miniature, and the default lands a hair under the ceiling it
// was measured to sit far inside.
func TestThePluginsEntryExcludesTheMarketplaces(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".claude", "plugins", "marketplaces"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Found by path rather than by position, so reordering the table
	// cannot quietly leave the cache in the copy.
	listed := Profile()
	var plugins *config.Entry
	for i := range listed {
		if listed[i].Path == ".claude/plugins" {
			plugins = &listed[i]
			break
		}
	}
	if plugins == nil {
		t.Fatalf(".claude/plugins exists here but was not listed: %v", pathsOf(listed))
	}
	for _, mask := range plugins.Exclude {
		// Bare, because an exclusion that carried a depth of its own
		// would stop at that depth and let the cache through below it.
		if mask.Pattern == "marketplaces/**" && mask.Bare() {
			return
		}
	}
	t.Errorf(".claude/plugins came back with exclude %v, which does not keep the marketplaces cache out", plugins.Exclude)
}

// TestADirectoryEntrySurvivesTheExistenceFilter is the behavior the old
// filter refused outright: it kept regular files only, because a name that
// happened to be a directory on somebody's machine would have been copied
// whole, unasked. The directories the default names now are named on
// purpose and measured, and dropping them for not being files would copy
// the credentials and lose the skills.
func TestADirectoryEntrySurvivesTheExistenceFilter(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".claude", "skills"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, entry := range Profile() {
		if entry.Path == ".claude/skills" {
			return
		}
	}
	t.Errorf(".claude/skills exists as a directory and was not listed: %v", pathsOf(Profile()))
}

func TestProfileEntriesAreRelativeAndSlashed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)

	place(t, filepath.Join(home, "AppData", "Local", "rush", "rush.json"), "x")

	var found bool
	for _, entry := range Profile() {
		if filepath.IsAbs(filepath.FromSlash(entry.Path)) {
			t.Errorf("%q is not relative to the profile root", entry.Path)
		}
		if strings.Contains(entry.Path, "\\") {
			t.Errorf("%q carries a backslash, which ktav reads as an escape", entry.Path)
		}
		if entry.Path == "AppData/Local/rush/rush.json" {
			found = true
		}
	}
	if !found {
		t.Errorf("a nested default was not listed as a relative, slashed path: %v", pathsOf(Profile()))
	}
}

// TestProfileStaysInsideTheProfileRoot covers a machine where APPDATA is
// redirected off the profile root entirely. The copier this list feeds only
// knows how to place something at a relative spot under a sandbox's own
// profile, so every entry is named relative to the profile root and looked
// for there -- one that is somewhere else is simply not found, rather than
// turned into a path that climbs out with "..".
func TestProfileStaysInsideTheProfileRoot(t *testing.T) {
	home := t.TempDir()
	elsewhere := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(elsewhere, "Roaming"))

	place(t, filepath.Join(elsewhere, "Roaming", "Codex", "auth.json"), "x")
	// One entry that does resolve under the profile root, so the checks
	// below walk a list that has something in it.
	place(t, filepath.Join(home, ".claude", ".credentials.json"), "{}")

	listed := Profile()
	for _, entry := range listed {
		if strings.HasPrefix(entry.Path, "..") || filepath.IsAbs(filepath.FromSlash(entry.Path)) {
			t.Errorf("an out-of-root entry leaked into the list: %q", entry.Path)
		}
		if entry.Path == "AppData/Roaming/Codex/auth.json" {
			t.Errorf("%q was listed, and APPDATA points away from the profile root here", entry.Path)
		}
	}
}

func place(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// pathsOf is what a failure about the default prints, so an error names
// paths rather than structs.
func pathsOf(entries []config.Entry) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Path)
	}
	return out
}
