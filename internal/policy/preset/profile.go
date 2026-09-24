package preset

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// defaultProfile is what a sandbox is given of an agent's own, and it comes
// in three kinds: credentials, settings, and instructions -- the agents,
// commands, skills and memory files people write for their tools. The old
// list carried only the first two and missed the third entirely, because
// instructions live in directories and naming a directory meant carrying
// everything inside it. An agent in a sandbox could log in but had none of
// what it had been taught, which is also the part a person cannot retype on
// every run.
//
// The list came to roughly 3 MB across about 270 files, against
// 254 KB for the file-only default it replaces and the 64 MB ceiling
// internal/policy/profile.Ceiling enforces. It stays that small because
// every directory in it was chosen by measurement: `.claude/skills` is
// 1.5 MB and 104 files, `.claude/agents` 244 KB and 50, `.claude/commands`
// 112 KB, `.claude/output-styles` 8 KB, `.codex/agents` 92 KB,
// `.gemini/commands` 32 KB, and every single file under 10 KB.
//
// One entry is named wide and bounded. `.claude/plugins` measured 44 MB, of
// which almost all -- 1,139 files -- was `marketplaces`, a cache of other
// people's plugin repositories, so the entry carries an exclusion. The
// exclusion does two things at once: it keeps the cache out of the copy,
// and it tells the copier that whatever sits under that name in the
// sandbox is the sandbox's to keep rather than something a later run
// deletes for not being in the source.
//
// What is still left behind is what made naming a whole agent directory a
// disaster. The default that did it was measured at 72,320 files and
// 19,436 MB into every sandbox on every run; on the machine these numbers
// come from, `.claude/projects` alone was 9.2 GB and `.codex/sessions`
// 4.5 GB of session history. None of that is reachable from this list, and
// the guard that keeps it from coming back -- no bare entry naming a whole
// agent directory -- is a test in this package, not a filter here, because
// a filter that refused every directory would refuse the instructions the
// list exists to carry.
//
// Two absences are deliberate rather than oversights. `AppData/Local/rush/
// providers.json` is a 517 KB catalog the tool re-fetches by itself, so
// copying it buys nothing and costs more than everything on the Gemini and
// rush lines put together. And OpenCode is named by its one settings file
// rather than by `.config/opencode`, which also holds a `node_modules`
// tree: naming the directory would need an exclusion to say what naming
// the file says plainly.
//
// The six agents measured above get directories; the rest keep the named
// credential files they always had. That line is where the measuring
// stopped, not where the list's ambition did: a directory named without
// somebody having counted what is in it is exactly how the 19 GB default
// happened, and none of those agents is installed here to count. Whoever
// has one and wants its instructions adds the directory to their own rules
// file, having seen what is in it.
//
// It is a starting point rather than a closed set. Agents appear faster
// than releases, the list is written into the rules file where it can be
// edited, and a name that is not on this machine is simply not copied.
var defaultProfile = []config.Entry{
	{Path: ".claude.json"},
	{Path: ".claude/.credentials.json"},
	{Path: ".claude/settings.json"},
	{Path: ".claude/keybindings.json"},
	{Path: ".claude/CLAUDE.md"},
	{Path: ".claude/agents"},
	{Path: ".claude/commands"},
	{Path: ".claude/skills"},
	{Path: ".claude/output-styles"},
	{Path: ".claude/plugins", Exclude: config.Masks([]string{"marketplaces/**"})},
	// cah's cache has many generated files; its bin and lib are the program.
	{Path: ".claude/cah-bin", Exclude: config.Masks([]string{"cache/**"})},
	{Path: ".codex/auth.json"},
	{Path: ".codex/config.toml"},
	{Path: ".codex/installation_id"},
	{Path: ".codex/AGENTS.md"},
	{Path: ".codex/agents"},
	{Path: "AppData/Roaming/Codex/auth.json"},
	{Path: ".gemini/settings.json"},
	{Path: ".gemini/google_accounts.json"},
	{Path: ".gemini/.env"},
	{Path: ".gemini/installation_id"},
	{Path: ".gemini/commands"},
	{Path: ".config/opencode/opencode.json"},
	{Path: ".crush/crush.json"},
	{Path: ".crush/commands"},
	{Path: ".config/rush/rush.json"},
	{Path: ".config/rush/commands"},
	{Path: "AppData/Local/rush/rush.json"},
	// The agents nobody measured, carrying what they always carried. They
	// are here because taking them out would log somebody out of a tool
	// that has been working for them, and a list gaining directories for
	// six agents is no reason for the other seven to lose what they had.
	{Path: ".qwen/oauth_creds.json"},
	{Path: ".qwen/settings.json"},
	{Path: ".qwen/installation_id"},
	{Path: ".factory/auth.encrypted"},
	{Path: ".factory/settings.json"},
	{Path: ".grok/settings.json"},
	{Path: ".zai/settings.json"},
	{Path: ".continue/config.yaml"},
	{Path: ".continue/config.json"},
	{Path: ".cagent/config.yaml"},
	{Path: "AppData/Roaming/Goose/config.yaml"},
}

// Profile lists the default entries for the rules file's profile section:
// the entries above that exist on this machine, each named as a path
// relative to the profile root, so a copy can be placed at the same relative
// spot under a sandbox's own profile.
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
func Profile() []config.Entry {
	home := paths.Home()
	guarded := make(map[string]bool, len(sensitive))
	for _, entry := range sensitive {
		guarded[strings.ToLower(entry.name)] = true
	}
	var out []config.Entry
	for _, entry := range defaultProfile {
		// The first segment is what the sensitive table names, so a file
		// under a protected directory is refused along with the directory.
		if guarded[strings.ToLower(firstSegment(entry.Path))] {
			continue
		}
		// Whatever is there, file or directory. This used to refuse
		// anything that was not a plain file, and the reason was sound
		// while the list named only files: a name that happened to be a
		// directory on somebody's machine would have been copied whole,
		// unasked. The list now names directories on purpose, so the guard
		// would refuse exactly what it was extended to carry. What it was
		// protecting against is a test in this package instead -- no bare
		// entry may name a whole agent state directory -- which refuses the
		// dangerous shape rather than every directory.
		if _, err := os.Stat(filepath.Join(home, filepath.FromSlash(entry.Path))); err != nil {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// RetiredProfileEntries are the whole agent state directories an older
// default filled a rules file's profile section with, each as a path relative
// to the profile root.
//
// Directories and nothing else, although that default wrote files too. The
// files it wrote are still right: ~/.claude.json is a credential file and is
// named by the narrow default as well. Counting it as the old default's doing
// made a rules file that said only `.claude.json` look like one that needed
// migrating, so every --init decided it had found the old list and appended
// the whole current default again -- and an entry somebody deleted came back
// on the next run. Measured from the report; the test that was supposed to
// cover this used an empty profile, where the two sets do not overlap.
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
	dirs, _ := aiPaths()
	var out []string
	for _, path := range dirs {
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
