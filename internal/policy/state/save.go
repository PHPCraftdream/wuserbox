package state

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// Save writes the state file, creating the directory it belongs in. Asking
// where that directory is does not create it, so the making happens here,
// where something is actually written.
func (s *State) Save() error {
	// Anything written now carries the mark, so it is never adopted again.
	s.Marked = true
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(Path(s.Group)), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(Path(s.Group), append(data, '\n'), 0o644); err != nil {
		return err
	}
	// Bookkeeping must not be rewritable by the code the sandbox runs.
	return acl.Protect(Path(s.Group))
}
