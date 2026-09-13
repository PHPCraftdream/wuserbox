package state

import (
	"fmt"
	"strings"

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
		if strings.EqualFold(g.Path, path) {
			return i, true
		}
	}
	return 0, false
}

// Add applies a grant and records it. Repeating a grant that is already
// recorded does nothing; asking for a different access on the same path
// replaces it, so narrowing a directory from writable to readable takes
// effect instead of being silently ignored.
func (s *State) Add(path string, kind grant.Kind) error {
	index, found := s.find(path)
	if found && s.Grants[index].Kind == kind {
		return nil
	}
	if err := grant.Apply(s.SID, path, kind); err != nil {
		return err
	}
	if found {
		s.Grants[index].Kind = kind
	} else {
		s.Grants = append(s.Grants, grant.Spec{Path: path, Kind: kind})
	}
	return s.Save()
}

// Remove revokes a recorded grant and persists the state.
func (s *State) Remove(path string) error {
	index, found := s.find(path)
	if !found {
		return fmt.Errorf("%s is not granted to %s", path, s.Group)
	}
	if err := grant.Revoke(s.SID, path); err != nil {
		return err
	}
	s.Grants = append(s.Grants[:index], s.Grants[index+1:]...)
	return s.Save()
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
