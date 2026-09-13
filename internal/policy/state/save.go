package state

import (
	"encoding/json"
	"os"
	"wuserbox/internal/win/acl"
)

// Save writes the state file.
func (s *State) Save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(Path(s.Group), append(data, '\n'), 0o644); err != nil {
		return err
	}
	// Bookkeeping must not be rewritable by the code the sandbox runs.
	return acl.Protect(Path(s.Group))
}
