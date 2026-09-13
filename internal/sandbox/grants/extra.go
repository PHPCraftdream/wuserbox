package grants

import (
	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
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
