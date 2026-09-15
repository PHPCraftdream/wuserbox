// The directories the rules file names for a project, on top of whatever the
// preset offers.

package grants

import (
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
)

// Extra grants the directories passed on the command line for one invocation.
func Extra(s *state.State, writable, readable []string, repair bool) error {
	for _, list := range []struct {
		dirs []string
		kind grant.Kind
	}{{writable, grant.RW}, {readable, grant.RO}} {
		for _, dir := range list.dirs {
			resolved, err := paths.Resolve(dir)
			if err != nil {
				return err
			}
			if err := apply(s, resolved, list.kind, repair); err != nil {
				return err
			}
		}
	}
	return nil
}

// FromConfig grants the directories the standing rules list for this project.
// Entries that no longer exist on disk are skipped instead of failing the run.
//
// With repair set, every permission is applied again whether or not the record
// claims it is already in place, which is what makes a second init put back an
// entry that was removed by hand.
func FromConfig(s *state.State, repair bool) error {
	rules, err := config.Load()
	if err != nil {
		return err
	}
	for _, spec := range rules.GrantsFor(s.Dir) {
		if _, err := os.Stat(spec.Path); err != nil {
			continue
		}
		if err := apply(s, spec.Path, spec.Kind, repair); err != nil {
			return err
		}
	}
	return nil
}

// apply chooses between trusting the record and acting on the file system.
func apply(s *state.State, path string, kind grant.Kind, repair bool) error {
	if repair {
		return s.Ensure(path, kind)
	}
	return s.Add(path, kind)
}
