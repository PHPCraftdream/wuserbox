package config

import (
	"os"
	"path/filepath"
	"wuserbox/internal/win/acl"

	ktav "github.com/ktav-lang/golang"
)

const header = "## wuserbox: extra directories each project may write to.\n" +
	"## Edit with `wuserbox add-dir <dir>` / `wuserbox remove-dir <dir>`.\n" +
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
	if err := os.WriteFile(Path(), []byte(header+text), 0o644); err != nil {
		return err
	}
	// The rules decide what a sandbox may write to, so they must not be
	// writable by one. This also covers the file being created in the profile
	// root after a sandbox was granted the right to create files there.
	return acl.Protect(Path())
}
