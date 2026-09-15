package preset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileListsTheCredentialFilesThatExist(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)

	place(t, filepath.Join(home, ".claude", ".credentials.json"), "{}")

	entries := map[string]bool{}
	for _, e := range Profile() {
		entries[e] = true
	}
	if !entries[".claude/.credentials.json"] {
		t.Errorf("an existing credential file was left out: %v", Profile())
	}
	if entries[".codex/auth.json"] {
		t.Errorf("a credential file that does not exist was listed: %v", Profile())
	}
}

// TestTheDefaultListNamesFilesAndNotTrees is the guard on what the default
// costs. It was once the agent state directories whole, which measured
// 72,320 files and 19,436 MB copied into every sandbox on every run --
// transcripts, logs and SQLite databases, almost no credentials. A default
// that names a directory is a default that copies whatever grows inside it.
func TestTheDefaultListNamesFilesAndNotTrees(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)

	// Every candidate made to exist as a directory. Anything the list is
	// willing to name as a tree shows up here; a list of files names none.
	for _, entry := range credentialsAndSettings {
		if err := os.MkdirAll(filepath.Join(home, filepath.FromSlash(entry)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if listed := Profile(); len(listed) > 0 {
		t.Errorf("the default list would copy these as whole directories: %v", listed)
	}

	// And with the same names as files, it takes them.
	for _, entry := range credentialsAndSettings {
		path := filepath.Join(home, filepath.FromSlash(entry))
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
		place(t, path, "x")
	}
	if len(Profile()) != len(credentialsAndSettings) {
		t.Errorf("as files, %d of %d were listed", len(Profile()), len(credentialsAndSettings))
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
		if guarded[strings.ToLower(firstSegment(entry))] {
			t.Errorf("the default list copies %s, which the tool protects from sandboxes", entry)
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
		original := credentialsAndSettings
		credentialsAndSettings = append(append([]string{}, original...), candidate)
		listed := Profile()
		credentialsAndSettings = original
		for _, got := range listed {
			if got == candidate {
				t.Errorf("%s was listed, and %s is protected", candidate, entry.name)
			}
		}
	}
}

func TestProfileEntriesAreRelativeAndSlashed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)

	place(t, filepath.Join(home, "AppData", "Roaming", "Goose", "config.yaml"), "x")

	var found bool
	for _, e := range Profile() {
		if filepath.IsAbs(filepath.FromSlash(e)) {
			t.Errorf("%q is not relative to the profile root", e)
		}
		if strings.Contains(e, "\\") {
			t.Errorf("%q carries a backslash, which ktav reads as an escape", e)
		}
		if e == "AppData/Roaming/Goose/config.yaml" {
			found = true
		}
	}
	if !found {
		t.Errorf("a nested default was not listed as a relative, slashed path: %v", Profile())
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

	place(t, filepath.Join(elsewhere, "Roaming", "Goose", "config.yaml"), "x")

	for _, e := range Profile() {
		if strings.HasPrefix(e, "..") || filepath.IsAbs(filepath.FromSlash(e)) {
			t.Errorf("an out-of-root entry leaked into the list: %q", e)
		}
	}
}
