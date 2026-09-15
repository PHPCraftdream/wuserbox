package preset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileListsTheAgentDirectoriesThatExist(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))

	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}

	entries := map[string]bool{}
	for _, e := range Profile() {
		entries[e] = true
	}
	if !entries[".claude"] {
		t.Errorf("an existing agent directory was left out: %v", Profile())
	}
	if entries[".codex"] {
		t.Errorf("an agent directory that does not exist was listed: %v", Profile())
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
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o755); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}

	listed := Profile()
	if len(listed) == 0 {
		t.Fatal("the default list is empty here, so it would pass whatever it held")
	}
	for _, entry := range listed {
		if guarded[strings.ToLower(entry)] {
			t.Errorf("the default list copies %s, which the tool protects from sandboxes", entry)
		}
	}
}

func TestProfileEntriesAreRelativeAndSlashed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))

	nested := filepath.Join(home, "AppData", "Local", "claude-cli-nodejs")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, e := range Profile() {
		if filepath.IsAbs(filepath.FromSlash(e)) {
			t.Errorf("%q is not relative to the profile root", e)
		}
		if e == "AppData/Local/claude-cli-nodejs" {
			found = true
		}
	}
	if !found {
		t.Errorf("a nested default was not reduced to a relative, slashed path: %v", Profile())
	}
}

// TestProfileSkipsEntriesOutsideTheProfileRoot covers a machine where
// LOCALAPPDATA is redirected off the profile root entirely: the copier this
// list feeds only knows how to place something at a relative spot under a
// sandbox's own profile, so an entry it cannot express that way must be left
// out rather than turned into a path that climbs out with "..".
func TestProfileSkipsEntriesOutsideTheProfileRoot(t *testing.T) {
	home := t.TempDir()
	elsewhere := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(elsewhere, "Local"))
	t.Setenv("APPDATA", filepath.Join(elsewhere, "Roaming"))

	if err := os.MkdirAll(filepath.Join(elsewhere, "Local", "claude-cli-nodejs"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, e := range Profile() {
		if strings.HasPrefix(e, "..") || filepath.IsAbs(filepath.FromSlash(e)) {
			t.Errorf("an out-of-root entry leaked into the list: %q", e)
		}
	}
}
