package config

import (
	"path/filepath"

	ktav "github.com/ktav-lang/golang"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

const header = "## wuserbox: extra directories each project may write to, and the\n" +
	"## profile entries copied into a sandbox before a run.\n" +
	"## Edit with `wuserbox --add-dir <dir>` / `wuserbox --remove-dir <dir>`.\n" +
	"##\n" +
	"## projects: one entry per project, naming its directory and the extra\n" +
	"## directories it may write to (rw) and read (ro).\n" +
	"##\n" +
	"## profile: what is copied from your profile into a sandbox's own, before\n" +
	"## each run. An entry is a bare path, copied whole, or an object that puts\n" +
	"## limits on one:\n" +
	"##   { path: .codex, depth: 2, include: [*.json, *.toml], exclude: [sessions/**] }\n" +
	"## depth bounds how far below path to descend (0 = only the files directly\n" +
	"## in path, omitted = no limit). include keeps only files a mask matches;\n" +
	"## exclude drops files a mask matches and leaves alone whatever the sandbox\n" +
	"## already has there, so an excluded directory is the sandbox's to write in\n" +
	"## undisturbed. A mask in either list may carry its own depth, overriding\n" +
	"## the entry's for that one pattern: { mask: *.md, depth: 3 }.\n" +
	"##\n" +
	"## A mask is *, ? or ** and nothing else, matched without regard to case:\n" +
	"## * is any run of characters within one path segment, ? is one character,\n" +
	"## and ** is any number of whole segments, including none. A mask with no\n" +
	"## slash matches a file's own name, wherever it sits within the depth; a\n" +
	"## mask with a slash matches the path relative to the entry's own path.\n" +
	"##\n" +
	"## cleanup: globs, relative to the profile root, cleared from a sandbox's\n" +
	"## own profile before each run -- caches, logs and session stores the\n" +
	"## sandbox itself wrote. Same mask language as above. A glob that would\n" +
	"## reach NTUSER.DAT, or UsrClass.dat and the rest of what the profile\n" +
	"## service keeps beside it, is refused outright -- those are the sandbox's\n" +
	"## registry, not anything worth clearing, so `cleanup: [**]` is an error\n" +
	"## and not a very thorough sweep.\n" +
	"##\n" +
	"## Paths use forward slashes: ktav reads a backslash as an escape.\n"

// Save writes the config as ktav, storing paths with forward slashes so the
// file stays hand-editable.
func (c *Config) Save() error {
	out := Config{Projects: []Rule{}, Profile: []Entry{}}
	for _, entry := range c.Profile {
		// Rebuilt rather than reused: saving must not edit the rules this
		// process is still holding, so the caller's entry keeps whatever
		// spelling it was loaded with.
		slash := Entry{Path: filepath.ToSlash(entry.Path)}
		if entry.Depth != nil {
			depth := *entry.Depth
			slash.Depth = &depth
		}
		slash.Include = slashMasks(entry.Include)
		slash.Exclude = slashMasks(entry.Exclude)
		out.Profile = append(out.Profile, slash)
	}
	out.Cleanup = slashMasks(c.Cleanup)
	for _, p := range c.Projects {
		rule := Rule{Dir: filepath.ToSlash(p.Dir)}
		for _, d := range p.RW {
			rule.RW = append(rule.RW, filepath.ToSlash(d))
		}
		for _, d := range p.RO {
			rule.RO = append(rule.RO, filepath.ToSlash(d))
		}
		out.Projects = append(out.Projects, rule)
	}
	text, err := ktav.Dumps(out)
	if err != nil {
		return err
	}
	// Published whole, like the per-sandbox record: writing into the file
	// itself empties it first, and a run reading the rules at that moment saw
	// no projects and quietly went without the standing rules.
	//
	// The rules decide what a sandbox may write to, so they must not be
	// writable by one; that is applied to the finished copy, so it is in force
	// before the file is in place. This also covers the file being created in
	// the profile root after a sandbox was granted the right to create files
	// there.
	return paths.Publish(Path(), []byte(header+text), acl.Protect)
}

// slashMasks rebuilds a mask list with forward slashes, so a pattern typed
// with backslashes is stored the way the rest of the file spells a path. Nil
// stays nil: an absent list and an empty one mean the same thing to the
// copier, and only the absent one keeps the entry bare.
func slashMasks(masks []Mask) []Mask {
	if len(masks) == 0 {
		return nil
	}
	out := make([]Mask, 0, len(masks))
	for _, mask := range masks {
		slash := Mask{Pattern: filepath.ToSlash(mask.Pattern)}
		if mask.Depth != nil {
			depth := *mask.Depth
			slash.Depth = &depth
		}
		out = append(out, slash)
	}
	return out
}
