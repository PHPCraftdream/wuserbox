package state

import (
	"fmt"

	"github.com/PHPCraftdream/wuserbox/internal/base/trace"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

// Has reports whether path was already granted to this sandbox.
func (s *State) Has(path string) bool {
	_, found := s.find(path)
	return found
}

// Kind reports the access recorded for a path, and whether there is any.
func (s *State) Kind(path string) (grant.Kind, bool) {
	index, found := s.find(path)
	if !found {
		return "", false
	}
	return s.Grants[index].Kind, true
}

func (s *State) find(path string) (int, bool) {
	for i, g := range s.Grants {
		if config.SamePath(g.Path, path) {
			return i, true
		}
	}
	return 0, false
}

// Add records a permission, applying it unless the record already says the
// same thing. This is the fast path, used on every run, where the record can
// be trusted because nothing has claimed otherwise.
//
// Asking for a different access on the same path replaces it, so narrowing a
// directory from writable to readable takes effect instead of being silently
// ignored.
func (s *State) Add(path string, kind grant.Kind) error {
	return s.record(path, kind, false, true)
}

// Offer records a permission the sandbox should have unless somebody has
// already said otherwise about that path.
//
// This is how the agent preset hands over its directories. The preset runs on
// every start, and applying it the way a person's request is applied would
// undo that request: a directory narrowed with `grant ~/.claude --ro` would be
// writable again after the next plain run, without anything saying so.
func (s *State) Offer(path string, kind grant.Kind) error {
	if index, found := s.find(path); found && s.Grants[index].Explicit {
		return nil
	}
	// The record is trusted here, as it is for Add: repair goes through the
	// record afterwards, and applying the preset afresh on every start would
	// push inheritance down whole directory trees for nothing.
	return s.record(path, kind, false, false)
}

// Ensure applies a permission whether or not the record already claims it.
//
// The record is bookkeeping, not proof: an entry can be deleted by hand, or
// lost when a directory is replaced, and the record would go on insisting that
// all is well. Repairing a sandbox has to act on the file system rather than
// on what was written down about it.
func (s *State) Ensure(path string, kind grant.Kind) error {
	return s.record(path, kind, true, true)
}

func (s *State) record(path string, kind grant.Kind, always, explicit bool) (err error) {
	done := trace.Current().Phase("grant_root",
		trace.Field{Key: "path", Value: path},
		trace.Field{Key: "kind", Value: string(kind)})
	defer func() { done(err) }()
	index, found := s.find(path)
	// A change that was begun and never finished is not unchanged, whatever
	// the kind says: the record ran ahead of the file system, and the two have
	// to be brought together again.
	unchanged := found && s.Grants[index].Kind == kind && !s.Grants[index].Pending &&
		(s.Grants[index].Explicit || !explicit)
	if unchanged && !always {
		return nil
	}
	if unchanged {
		// The record already says this; only the file system needs putting
		// back, which is what repair is for.
		return grant.Apply(s.SID, path, kind, s.paths())
	}
	before := append([]grant.Spec(nil), s.Grants...)
	if found {
		s.Grants[index].Kind = kind
		// A path the preset offers is not made anonymous by being offered
		// again: only asking for it by hand sets the mark, and nothing here
		// takes it away.
		s.Grants[index].Explicit = s.Grants[index].Explicit || explicit
		s.Grants[index].Pending = true
	} else {
		s.Grants = append(s.Grants,
			grant.Spec{Path: path, Kind: kind, Explicit: explicit, Pending: true})
	}
	// Written down first, handed over second. The two can only fail one way
	// round without harm: a permission in force that the record does not
	// mention cannot be found again, because explain does not list it and
	// revoke does not know about it, while a record claiming more than is in
	// force is reported by explain and put right by init.
	if err := s.Save(); err != nil {
		s.Grants = before
		return err
	}
	if err := grant.Apply(s.SID, path, kind, s.paths()); err != nil {
		s.Grants = before
		if saveErr := s.Save(); saveErr != nil {
			return fmt.Errorf("%w (and the record still claims it, because %w)", err, saveErr)
		}
		return err
	}
	if !found {
		s.markFresh(path, kind)
	}
	// Making a directory read-only has to reach what is inside it: a
	// permission set directly on a subdirectory is read before the refusal
	// handed down from here, and would go on allowing what this just refused.
	//
	// This happens before the change is settled, so the mark stands for the
	// whole of it. Settling first would leave a stop in between invisible:
	// writable subdirectories under a read-only parent, and nothing marked for
	// anyone to finish.
	if !kind.Writable() {
		if err := s.narrow(path); err != nil {
			return err
		}
		// Narrowing has the same corner as revoking: a directory inside this
		// one that was handed to another sandbox pinned its list while this
		// sandbox still had the run of the place, and keeps that copy until
		// it is taken away by name.
		if err := grant.Prune(s.SID, path, s.paths()); err != nil {
			return err
		}
	}
	// The record and the file system agree again.
	return s.settle(path)
}

// Remove revokes a recorded grant and persists the state.
func (s *State) Remove(path string) error {
	index, found := s.find(path)
	if !found {
		return fmt.Errorf("%s is not granted to %s", path, s.Group)
	}
	if err := grant.Revoke(s.SID, path, s.paths()); err != nil {
		return err
	}
	// Rewriting this directory is not the whole of taking it back. A
	// directory inside it that was handed to another sandbox had its
	// permission list pinned, this sandbox's entry copied into it, and it no
	// longer hears from here — so the entry has to be taken away by name, or
	// the sandbox keeps writing in a corner of what it just lost.
	s.Grants = append(s.Grants[:index], s.Grants[index+1:]...)
	if err := grant.Prune(s.SID, path, s.paths()); err != nil {
		return err
	}
	return s.Save()
}

// paths lists every path this sandbox holds.
func (s *State) paths() []string {
	out := make([]string, 0, len(s.Grants))
	for _, g := range s.Grants {
		out = append(out, g.Path)
	}
	return out
}

// WritablePaths lists the paths this sandbox may change.
func (s *State) WritablePaths() []string {
	var out []string
	for _, g := range s.Grants {
		if g.Kind.Writable() {
			out = append(out, g.Path)
		}
	}
	return out
}

// WritableSpecs lists the grants this sandbox may change anything under,
// with their kinds, so a caller can tell a granted file from a granted
// directory.
func (s *State) WritableSpecs() []grant.Spec {
	var out []grant.Spec
	for _, g := range s.Grants {
		if g.Kind.Writable() {
			out = append(out, g)
		}
	}
	return out
}
