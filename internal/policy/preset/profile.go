package preset

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
)

// credentialsAndSettings is what a sandbox is given of an agent's own: the
// file it logs in with and the file it is configured by. Not the directory
// holding them.
//
// That distinction is the whole of this list, and it was learned the
// expensive way. The default was once the agent state directories whole --
// the same list AI() knows -- and it was measured, on one ordinary machine,
// at 72,320 files and 19,436 MB, copied into every sandbox on every run.
// Almost none of it was credentials. `.codex` came to 7.2 GB of which two
// SQLite databases of conversation history were 1.9 GB; `.claude` came to
// 10 GB of project transcripts; `.config` came to 129 MB of which 82 MB was
// a note-taking application that is not an agent at all. What an agent
// actually needs to start logged in and configured is measured in kilobytes.
//
// So this names files. A history, a log, a cache or a database is left
// behind on purpose: a sandbox starts with your login and your settings and
// a blank history, which is also the more useful answer -- one project's
// transcripts have no business inside another project's sandbox.
//
// It is a starting point rather than a closed set. Agents appear faster than
// releases, the list is written into the rules file where it can be edited,
// and a name that is not on this machine is simply not copied. Anyone who
// wants a directory copied whole can say so there; what they cannot do is
// get one by accident.
var credentialsAndSettings = []string{
	".claude.json",
	".claude/.credentials.json", ".claude/settings.json",
	".claude/CLAUDE.md", ".claude/keybindings.json",
	".codex/auth.json", ".codex/config.toml",
	".gemini/settings.json", ".gemini/google_accounts.json",
	".gemini/.env", ".gemini/installation_id",
	".qwen/oauth_creds.json", ".qwen/settings.json", ".qwen/installation_id",
	".factory/auth.encrypted", ".factory/settings.json",
	".grok/settings.json",
	".crush/crush.json",
	".zai/settings.json",
	".continue/config.yaml", ".continue/config.json",
	".cagent/config.yaml",
	"AppData/Roaming/Goose/config.yaml",
	"AppData/Roaming/Codex/auth.json",
}

// Profile lists the default entries for the rules file's profile section:
// the credential and settings files above that exist on this machine, each
// as a path relative to the profile root, so a copy can be placed at the
// same relative spot under a sandbox's own profile.
//
// What is deliberately not here is anything on the sensitive list -- ~/.ssh,
// ~/.netrc, ~/.npmrc, ~/.gitconfig and their neighbors. wuserbox protects
// those from sandboxes on purpose, so that handing over a home directory does
// not hand over the keys in it, and a default that copied them into every
// sandbox would undo that for everybody at once, quietly, on a first run
// nobody was watching. An agent's own credentials and the machine owner's
// keys are different things; this list is for the first.
//
// Somebody who wants their git identity or an ssh key inside a sandbox adds
// the name to the rules file themselves. That is a deliberate act with a
// consequence they chose, and a default does not get to choose it for them.
//
// Only entries that exist here are listed, because most of a list built for
// every agent this project knows about will not exist for a given person,
// and a name that never resolves to anything would sit in every fresh rules
// file unexplained.
func Profile() []string {
	home := paths.Home()
	guarded := make(map[string]bool, len(sensitive))
	for _, entry := range sensitive {
		guarded[strings.ToLower(entry.name)] = true
	}
	var out []string
	for _, entry := range credentialsAndSettings {
		// The first segment is what the sensitive table names, so a file
		// under a protected directory is refused along with the directory.
		if guarded[strings.ToLower(firstSegment(entry))] {
			continue
		}
		info, err := os.Stat(filepath.Join(home, filepath.FromSlash(entry)))
		if err != nil {
			continue
		}
		// A plain file or nothing. The whole point of naming files is that
		// the default cannot grow into a tree, and a name that happens to be
		// a directory on somebody's machine would do exactly that -- copied
		// whole, on every run, without anybody having asked for it. Whoever
		// wants that says so in the rules file.
		if !info.Mode().IsRegular() {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// RetiredProfileEntries are what a rules file's profile section used to be
// filled with: the agent state directories, whole, each as a path relative to
// the profile root.
//
// Worth recognizing because they are still on disk. A rules file is written
// once and kept, so a machine that ran that version still carries that list,
// still copies whole trees into every sandbox on every run, and would go on
// doing so however narrow the default becomes afterwards. On the machine this
// was measured on that came to 72,320 files and 19,436 MB a run.
//
// Derived from the same place the old default derived it rather than copied
// into a table here, so the two cannot drift apart. Unlike that default this
// does not skip what is missing: a rules file can name a directory that has
// since been deleted, and the name still has to be recognized as the old
// default's doing rather than as somebody's own addition.
func RetiredProfileEntries() []string {
	home := paths.Home()
	dirs, files := aiPaths()
	var out []string
	for _, path := range append(append([]string{}, dirs...), files...) {
		rel, err := filepath.Rel(home, path)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			continue
		}
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

func firstSegment(entry string) string {
	if cut := strings.IndexByte(filepath.ToSlash(entry), '/'); cut >= 0 {
		return entry[:cut]
	}
	return entry
}
