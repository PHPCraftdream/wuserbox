package config

import (
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

// RuleFor returns the rule for a project directory. With create set it appends
// an empty rule when none exists, so callers can add paths to it.
func (c *Config) RuleFor(dir string, create bool) *Rule {
	for i := range c.Projects {
		if SamePath(c.Projects[i].Dir, dir) {
			return &c.Projects[i]
		}
	}
	if !create {
		return nil
	}
	c.Projects = append(c.Projects, Rule{Dir: dir})
	return &c.Projects[len(c.Projects)-1]
}

// SamePath reports whether two spellings name the same place. Either side may
// be written the Windows way, the shell way, with a variable or with a tilde,
// so a file edited by hand matches what the commands pass in.
func SamePath(a, b string) bool {
	return strings.EqualFold(canonical(a), canonical(b))
}

// canonical reduces a path to one spelling. It falls back to a plain cleanup
// when the path cannot be resolved, so a rule for a directory that is gone
// still matches its own entry.
func canonical(path string) string {
	if resolved, err := paths.Resolve(path); err == nil {
		return resolved
	}
	return filepath.Clean(filepath.FromSlash(strings.Trim(strings.TrimSpace(path), `"'`)))
}

// GrantsFor turns the rule for a project directory into grant specs, with
// every path reduced to its real location.
func (c *Config) GrantsFor(dir string) []grant.Spec {
	rule := c.RuleFor(dir, false)
	if rule == nil {
		return nil
	}
	var out []grant.Spec
	for _, list := range []struct {
		dirs []string
		kind grant.Kind
	}{{rule.RW, grant.RW}, {rule.RO, grant.RO}} {
		for _, dir := range list.dirs {
			resolved, err := paths.Resolve(dir)
			if err != nil {
				continue
			}
			out = append(out, grant.Spec{Path: resolved, Kind: list.kind})
		}
	}
	return out
}
