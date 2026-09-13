package state

import (
	"fmt"
	"strings"

	"wuserbox/internal/policy/grant"
)

// Has reports whether path was already granted to this sandbox.
func (s *State) Has(path string) bool {
	for _, g := range s.Grants {
		if strings.EqualFold(g.Path, path) {
			return true
		}
	}
	return false
}

// Add applies a grant unless it is already recorded, then persists the state.
func (s *State) Add(path string, kind grant.Kind) error {
	if s.Has(path) {
		return nil
	}
	if err := grant.Apply(s.SID, path, kind); err != nil {
		return err
	}
	s.Grants = append(s.Grants, grant.Spec{Path: path, Kind: kind})
	return s.Save()
}

// Remove revokes a recorded grant and persists the state.
func (s *State) Remove(path string) error {
	index := -1
	for i, g := range s.Grants {
		if strings.EqualFold(g.Path, path) {
			index = i
			break
		}
	}
	if index < 0 {
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
