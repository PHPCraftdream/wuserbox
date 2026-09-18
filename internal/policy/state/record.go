// The record as a file: where it lives, how it is published so nobody ever
// reads half of one, how it is read back, and how it is held while a command
// changes it.

package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/base/trace"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
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

// Path is the state file for a sandbox group.
func Path(group string) string {
	return filepath.Join(paths.StateDir(), group+".json")
}

// PreviousPath is the record as it stood before the last save.
//
// The record is the only list of what a sandbox was handed, and a sandbox
// outlives the file: entries naming it sit on directories all over the disk,
// and nothing else says where. If the file stops being readable, those
// directories can no longer be found by anything, so a copy of the last
// readable one is kept beside it. It is a second chance, not a second
// authority: it is read only when the record itself will not parse.
func PreviousPath(group string) string {
	return Path(group) + ".previous"
}

// OfferMany hands over several directories at once, and is how a sandbox is
// built without the wait being the sum of its parts.
//
// Handing a directory over means rewriting the access list of every file
// already inside it, because Windows copies an inheritable entry down rather
// than looking upwards when it is asked. On a working machine that is tens of
// thousands of files for the agent directories alone, and doing them one after
// another takes as long as all of them added together. They are independent of
// each other, so they are done at the same time and the wait becomes the
// largest single tree rather than the total.
//
// What is recorded is written once before the work and once after, rather than
// once per directory: the marks say a change was begun, so a run stopped in the
// middle is finished by the next one either way.
//
// Only offers are taken this way, and only the kinds that hand something over.
// Narrowing reaches inside a directory and changes the record as it goes, which
// is not something to do from several threads at once.
func (s *State) OfferMany(specs []grant.Spec) error {
	wanted := make([]grant.Spec, 0, len(specs))
	for _, spec := range specs {
		if !spec.Kind.Writable() {
			return s.oneByOne(specs)
		}
		if index, found := s.find(spec.Path); found &&
			(s.Grants[index].Explicit || (s.Grants[index].Kind == spec.Kind && !s.Grants[index].Pending)) {
			// Somebody has said otherwise about this path, or it is already
			// held and finished: either way there is nothing to do.
			continue
		}
		wanted = append(wanted, grant.Spec{Path: spec.Path, Kind: spec.Kind, Pending: true})
	}
	if len(wanted) == 0 {
		return nil
	}

	before := append([]grant.Spec(nil), s.Grants...)
	for _, spec := range wanted {
		if index, found := s.find(spec.Path); found {
			s.Grants[index].Kind = spec.Kind
			s.Grants[index].Pending = true
		} else {
			s.Grants = append(s.Grants, spec)
		}
	}
	if err := s.Save(); err != nil {
		s.Grants = before
		return err
	}
	if err := ApplyTogether(s.SID, wanted, s.paths()); err != nil {
		// The record keeps the marks: it claims more than is in force, which
		// the next run finishes and explain reports meanwhile. That is the
		// harmless way round, so the error is worth reporting as it is.
		return err
	}
	for _, spec := range wanted {
		if index, found := s.find(spec.Path); found {
			s.Grants[index].Pending = false
		}
	}
	return s.Save()
}

// oneByOne is the ordinary path, for anything OfferMany will not take.
func (s *State) oneByOne(specs []grant.Spec) error {
	for _, spec := range specs {
		if err := s.Offer(spec.Path, spec.Kind); err != nil {
			return err
		}
	}
	return nil
}

// ApplyTogether applies permissions on several paths at the same time, a few
// at once rather than all of them: each one keeps a whole directory tree busy,
// and the disk is the limit long before the processor is.
//
// pinned is the record's own paths for this account, passed straight through
// to every Apply: the sweep each one runs needs it to tell an object the
// operator pinned in its own right from one a sandbox only made to look that
// way (owner.go).
func ApplyTogether(account string, specs []grant.Spec, pinned []string) error {
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers > len(specs) {
		workers = len(specs)
	}
	queue := make(chan grant.Spec)
	failures := make(chan error, len(specs))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for spec := range queue {
				done := trace.Current().Phase("grant_root",
					trace.Field{Key: "path", Value: spec.Path},
					trace.Field{Key: "kind", Value: string(spec.Kind)})
				err := grant.Apply(account, spec.Path, spec.Kind, pinned)
				done(err)
				if err != nil {
					failures <- err
				}
			}
		}()
	}
	for _, spec := range specs {
		queue <- spec
	}
	close(queue)
	wg.Wait()
	close(failures)

	var all []error
	for err := range failures {
		all = append(all, err)
	}
	if len(all) > 0 {
		return errors.Join(all...)
	}
	return nil
}
