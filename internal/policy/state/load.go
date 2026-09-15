package state

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
)

// Load reads the state for a group, returning nil when the sandbox has never
// been initialized.
//
// A record that is there and will not parse is not the same thing as no record
// at all, and the difference matters: the first means a sandbox exists with
// permissions in force somewhere, and reading it as the second would hand out a
// fresh one and leave those behind. So it comes back as Damaged, carrying
// whatever the copy from before the last save still says, and every caller
// decides for itself. Most should stop. Removal should not: clearing up after
// exactly this is what it is for.
func Load(group string) (*State, error) {
	data, err := paths.ReadWhole(Path(group))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s, err := parse(data)
	if err == nil {
		return s, nil
	}
	return nil, &Damaged{Path: Path(group), Err: err, Previous: lastReadable(group)}
}

// Damaged is a record that exists and cannot be read.
type Damaged struct {
	Path string
	Err  error
	// Previous is the record as it stood before the last save, when that copy
	// is still readable, and nil when it is not. It can be a save behind, so a
	// directory handed over since is missing from it; everything older is
	// there, which is the part nothing else could name.
	Previous *State
}

func (d *Damaged) Error() string {
	return fmt.Sprintf("the record at %s cannot be read: %v", d.Path, d.Err)
}

func (d *Damaged) Unwrap() error { return d.Err }

// lastReadable returns the kept copy of the record, or nil if there is none or
// it is no better than the record itself.
func lastReadable(group string) *State {
	data, err := paths.ReadWhole(PreviousPath(group))
	if err != nil {
		return nil
	}
	s, err := parse(data)
	if err != nil {
		return nil
	}
	return s
}

// parse reads one record and brings it up to date.
func parse(data []byte) (*State, error) {
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
