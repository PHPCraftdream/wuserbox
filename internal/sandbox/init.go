package sandbox

import (
	"os"
	"path/filepath"

	"wuserbox/internal/paths"
	"wuserbox/internal/policy/grant"
	"wuserbox/internal/policy/preset"
	"wuserbox/internal/policy/state"
	"wuserbox/internal/sandbox/grants"
	"wuserbox/internal/win/group"
	"wuserbox/internal/win/sid"
)

// Init creates the group if it is missing and applies every permission the
// sandbox should hold: its own temp directory, the project directory, the
// agent preset, the standing rules and the extra directories passed in.
// Creating a group needs administrator rights; changing permissions needs
// ownership of the target.
func Init(o Options) (*state.State, error) {
	name, dir, err := Name(o.Dir)
	if err != nil {
		return nil, err
	}
	if comment, exists, err := group.Comment(name); err != nil {
		return nil, err
	} else if !exists {
		if err := group.Add(name, dir); err != nil {
			return nil, err
		}
	} else if comment != dir {
		group.SetComment(name, dir)
	}

	account, err := sid.Lookup(name)
	if err != nil {
		return nil, err
	}
	s, err := state.Load(name)
	if err != nil {
		return nil, err
	}
	if s == nil {
		s = &state.State{Group: name, Dir: dir, Temp: filepath.Join(paths.StateDir(), "tmp", name)}
	}
	s.SID = account.String()

	if err := os.MkdirAll(s.Temp, 0o755); err != nil {
		return nil, err
	}
	if err := s.Add(s.Temp, grant.RW); err != nil {
		return nil, err
	}
	if err := s.Add(dir, grant.RW); err != nil {
		return nil, err
	}
	if err := applyPreset(s, o); err != nil {
		return nil, err
	}
	if err := grants.FromConfig(s); err != nil {
		return nil, err
	}
	if err := grants.Extra(s, o.RW, o.RO); err != nil {
		return nil, err
	}
	if err := s.Save(); err != nil {
		return nil, err
	}
	return s, grants.ProtectSettings(s)
}

func applyPreset(s *state.State, o Options) error {
	if o.NoAI {
		return nil
	}
	for _, spec := range preset.AI() {
		if err := s.Add(spec.Path, spec.Kind); err != nil {
			return err
		}
	}
	if !o.HomeWrites {
		return nil
	}
	home := preset.Home()
	if err := s.Add(home.Path, home.Kind); err != nil {
		return err
	}
	// That permission reaches every file already in the profile root, so
	// refuse the ones that were never meant for the sandbox.
	return grants.RefuseHomeFiles(s)
}
