package config

import (
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
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
	return Identity(a) == Identity(b)
}

// Identity returns the comparison key SamePath derives for one side of a
// question: the spelling reduced to its real location the way every command
// reduces the paths it is given, then the filesystem's directory-entry
// spelling of that, ASCII case folded and nothing more -- or the clean
// spelling under a fallback prefix when it names nothing. SamePath resolves
// both sides again for every question; a caller with many paths to compare
// resolves each side once through this and compares keys itself.
func Identity(path string) string {
	return identity(canonical(path))
}

// identity uses the filesystem's directory-entry spelling when it can, and
// only folds ASCII in the missing-path fallback. Unicode EqualFold is not a
// Windows path comparison: NTFS can keep K and the Kelvin sign apart.
func identity(path string) string {
	if key, err := pathid.Key(path); err == nil {
		return asciiFold(key)
	}
	return "fallback:" + asciiFold(filepath.Clean(path))
}

func asciiFold(path string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, path)
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
