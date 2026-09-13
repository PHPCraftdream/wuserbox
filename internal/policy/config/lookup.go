package config

import (
	"path/filepath"
	"strings"

	"wuserbox/internal/paths"
	"wuserbox/internal/policy/grant"
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

// SamePath compares two paths that may differ in slash direction or case.
func SamePath(a, b string) bool {
	return strings.EqualFold(
		filepath.Clean(filepath.FromSlash(a)),
		filepath.Clean(filepath.FromSlash(b)),
	)
}

// GrantsFor turns the rule for a project directory into grant specs.
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
