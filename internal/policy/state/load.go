package state

import (
	"encoding/json"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
)

// Load reads the state for a group, returning nil when the sandbox has never
// been initialized.
func Load(group string) (*State, error) {
	data, err := paths.ReadWhole(Path(group))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	adopt(&s)
	return &s, nil
}

// adopt brings a record written by an earlier build up to date.
//
// Its entries predate the mark that tells a request apart from an offer, and
// nothing in the file says which they were. They are taken as requests: a
// directory somebody narrowed by hand keeps its narrowing across the upgrade,
// and a directory the preset would have handed over anyway is unaffected,
// because the preset asks for the same access it already holds.
func adopt(s *State) {
	if s.Marked {
		return
	}
	for i := range s.Grants {
		s.Grants[i].Explicit = true
	}
	s.Marked = true
}
