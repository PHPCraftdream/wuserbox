package grant

// Spec is one path plus the access a sandbox should have on it.
type Spec struct {
	Path string `json:"path"`
	Kind Kind   `json:"kind"`
}
