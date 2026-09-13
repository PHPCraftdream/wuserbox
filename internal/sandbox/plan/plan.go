package plan

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
