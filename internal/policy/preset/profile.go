package preset

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
)

// Profile lists the default entries for the rules file's profile section: the
// state directories of the agents AI() already knows about, each reduced to a
// path relative to the profile root, so that a copy can be placed at the same
// relative spot under a sandbox's own profile.
//
// What is deliberately not here is anything on the sensitive list -- ~/.ssh,
// ~/.netrc, ~/.npmrc, ~/.gitconfig and their neighbors. wuserbox protects
// those from sandboxes on purpose, so that handing over a home directory does
// not hand over the keys in it, and a default that copied them into every
// sandbox would undo that for everybody at once, quietly, on a first run
// nobody was watching. An agent's own credentials and the machine owner's keys
// are different things; this list is for the first.
//
// Somebody who wants their git identity or an ssh key inside a sandbox adds
// the name to the rules file themselves. That is a deliberate act with a
// consequence they chose, and a default does not get to choose it for them.
//
// Only entries that exist on this machine are listed, the same restriction
// AI() applies to itself: most of a list built for every agent this project
// knows about will not exist for a given person, and a name that never
// resolves to anything would sit in every fresh rules file unexplained.
//
// An entry outside the profile root is left out rather than turned into a path
// with ".." in it: LOCALAPPDATA and APPDATA are redirected off the profile root
// on some machines, and the copier this list feeds only knows how to place
// something at a relative spot under a sandbox's profile.
func Profile() []string {
	home := paths.Home()
	var out []string
	for _, spec := range AI() {
		rel, err := filepath.Rel(home, spec.Path)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			continue
		}
		if _, err := os.Stat(spec.Path); err != nil {
			continue
		}
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}
