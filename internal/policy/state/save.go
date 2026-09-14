package state

import (
	"encoding/json"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// Save writes the state file, creating the directory it belongs in. Asking
// where that directory is does not create it, so the making happens here,
// where something is actually written.
//
// The record is published whole, and protected before it is published, so the
// permissions travel with the file: there is no moment where the record is in
// place and still open to the code the sandbox runs.
func (s *State) Save() error {
	// Anything written now carries the mark, so it is never adopted again.
	s.Marked = true
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return paths.Publish(Path(s.Group), append(data, '\n'), acl.Protect)
}
