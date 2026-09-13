// Package plan works out what a sandbox would be given, without giving it.
// The answer drives both --dry-run, which shows it before anything happens,
// and explain, which compares it against what is really in place.
package plan

import "github.com/PHPCraftdream/wuserbox/internal/policy/grant"

// Entry is one directory a sandbox would hold, and where that came from.
type Entry struct {
	Path   string     `json:"path"`
	Kind   grant.Kind `json:"kind"`
	Source Source     `json:"source"`
}

// Source is the reason a directory is in the plan. Knowing it is the
// difference between "someone asked for this" and "wuserbox decided for you".
type Source string

const (
	// FromProject is the project directory itself.
	FromProject Source = "project"
	// FromTemp is the sandbox's own temporary directory.
	FromTemp Source = "temp"
	// FromPreset is the built-in list of AI agent directories.
	FromPreset Source = "preset"
	// FromRules is the rules file in the profile root.
	FromRules Source = "rules"
	// FromFlags is --rw or --ro on this command line.
	FromFlags Source = "flags"
)
