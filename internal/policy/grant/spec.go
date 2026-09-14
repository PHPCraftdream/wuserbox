package grant

// Spec is one path plus the access a sandbox should have on it.
type Spec struct {
	Path string `json:"path"`
	Kind Kind   `json:"kind"`
	// Explicit marks a permission somebody asked for: a grant, an add-dir, a
	// standing rule, a --rw or --ro on the command line. The agent preset
	// leaves those alone, so a directory narrowed by hand stays narrow
	// instead of being widened again by the next plain run.
	Explicit bool `json:"explicit,omitempty"`
}
