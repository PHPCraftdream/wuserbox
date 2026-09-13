package grants

import (
	"wuserbox/internal/paths"
	"wuserbox/internal/policy/grant"
	"wuserbox/internal/policy/state"
)

// Extra grants the directories passed on the command line for one invocation.
func Extra(s *state.State, writable, readable []string) error {
	for _, list := range []struct {
		dirs []string
		kind grant.Kind
	}{{writable, grant.RW}, {readable, grant.RO}} {
		for _, dir := range list.dirs {
			resolved, err := paths.Resolve(dir)
			if err != nil {
				return err
			}
			if err := s.Add(resolved, list.kind); err != nil {
				return err
			}
		}
	}
	return nil
}
