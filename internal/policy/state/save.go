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
	keepPrevious(s.Group)
	return paths.Publish(Path(s.Group), append(data, '\n'), acl.Protect)
}

// keepPrevious copies the record as it stands now to PreviousPath, so a record
// that later stops being readable still has something behind it naming the
// directories the sandbox holds.
//
// Failing to keep the copy does not stop the save. The copy is a second chance
// at the list, not the list, and refusing to record a grant because the spare
// copy could not be made would lose the very thing being protected.
func keepPrevious(group string) {
	current, err := paths.ReadWhole(Path(group))
	if err != nil {
		return
	}
	// Protected like the record itself: it says the same things about the same
	// directories, and the sandbox may not rewrite either of them.
	_ = paths.Publish(PreviousPath(group), current, acl.Protect)
}
