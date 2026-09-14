package config

import (
	"path/filepath"

	ktav "github.com/ktav-lang/golang"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

const header = "## wuserbox: extra directories each project may write to.\n" +
	"## Edit with `wuserbox --add-dir <dir>` / `wuserbox --remove-dir <dir>`.\n" +
	"## Paths use forward slashes: ktav reads a backslash as an escape.\n"

// Save writes the config as ktav, storing paths with forward slashes so the
// file stays hand-editable.
func (c *Config) Save() error {
	out := Config{Projects: []Rule{}}
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
