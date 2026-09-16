package plan

import "github.com/PHPCraftdream/wuserbox/internal/policy/profile"

// Plan is everything a sandbox would consist of.
type Plan struct {
	Group   string  `json:"group"`
	Dir     string  `json:"dir"`
	Temp    string  `json:"temp"`
	Entries []Entry `json:"entries"`
	// Reserved are the files in the profile root that would be taken as
	// empty placeholders so the sandbox cannot claim those names.
	Reserved []string `json:"reserved,omitempty"`
	// Unreserved are the ones that cannot be taken, because an empty file
	// would hide a shell startup file that is really there.
	Unreserved []string `json:"unreserved,omitempty"`
	// Cleanup is what the rules file's cleanup: globs would clear from the
	// sandbox's own profile, in a preview -- nothing is actually cleared.
	// Filled in by AddProfilePreview, not by For: see that method's own doc
	// for why building this is kept apart from the rest of the plan.
	Cleanup []profile.CleanupPlan `json:"cleanup,omitempty"`
	// Profile is what filling each profile: entry would do, in a preview --
	// nothing is actually copied. Filled in by AddProfilePreview.
	Profile []profile.EntryPlan `json:"profile,omitempty"`
}

// Writable lists the paths the plan would let the sandbox change.
func (p Plan) Writable() []string {
	var out []string
	for _, entry := range p.Entries {
		if entry.Kind.Writable() {
			out = append(out, entry.Path)
		}
	}
	return out
}
