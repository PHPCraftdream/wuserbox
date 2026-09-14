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
	// Pending marks a change written down but not yet applied. The record is
	// written first so that a permission can never be in force with nothing
	// pointing at it, which leaves the other order to guard against: a process
	// stopped in between would otherwise leave a record saying read-only while
	// the entries still say writable, and asking for read-only again would
	// trust the record and do nothing.
	Pending bool `json:"pending,omitempty"`
}
