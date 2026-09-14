package sandbox

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/lock"
	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/grants"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
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
	var built *state.State
	// Everything from reading the record to writing it back is one operation.
	// Another wuserbox working on the same sandbox waits here rather than
	// starting from a record this one is about to replace.
	if err := lock.Hold(name, func() error {
		built, err = build(name, dir, o)
		return err
	}); err != nil {
		return nil, err
	}
	return built, grants.ProtectSettings(built)
}

// build does the work of Init with the sandbox's record already held.
func build(name, dir string, o Options) (*state.State, error) {
	if comment, exists, err := group.Comment(name); err != nil {
		return nil, err
	} else if !exists {
		if err := group.Add(name, dir); err != nil {
			return nil, err
		}
	} else if comment != dir {
		// A stale comment is cosmetic: the group still works.
		_ = group.SetComment(name, dir)
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
	// Anything a stopped command left half done is finished before this one
	// builds on top of it.
	if err := s.FinishPending(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(s.Temp, 0o755); err != nil {
		return nil, err
	}
	if err := s.Ensure(s.Temp, grant.RW); err != nil {
		return nil, err
	}
	if err := s.Ensure(dir, grant.RW); err != nil {
		return nil, err
	}
	if err := applyPreset(s, o); err != nil {
		return nil, err
	}
	if err := grants.FromConfig(s, true); err != nil {
		return nil, err
	}
	if err := grants.Extra(s, o.RW, o.RO, true); err != nil {
		return nil, err
	}
	// Everything else the sandbox was ever given: a directory handed over
	// once with grant or --rw is in the record and nowhere else, and repair
	// has to reach it too, or the advice to run init again would only work
	// for some of the permissions.
	if err := grants.Reapply(s); err != nil {
		return nil, err
	}
	if err := s.Save(); err != nil {
		return nil, err
	}
	return s, nil
}

func applyPreset(s *state.State, o Options) error {
	if o.NoAI {
		// Skipping is not enough for a sandbox that already holds these
		// directories: the flag has to take them back, or a later run would
		// still reach them.
		return grants.DropPreset(s)
	}
	for _, spec := range preset.AI() {
		if err := s.Offer(spec.Path, spec.Kind); err != nil {
			return err
		}
	}
	if !o.HomeWrites {
		return nil
	}
	// Reserve the sensitive names before handing the directory over, so the
	// sandbox cannot create one of them first.
	unguarded, err := grants.ReserveSensitiveNames()
	if err != nil {
		return err
	}
	for _, path := range unguarded {
		if o.JSON {
			continue // the answer is one JSON document; prose would break it
		}
		fmt.Fprintf(os.Stderr, "wuserbox: %s does not exist and cannot be reserved; "+
			"the sandbox may create it\n", path)
	}
	home := preset.Home()
	if err := s.Ensure(home.Path, home.Kind); err != nil {
		return err
	}
	// That permission reaches every file already in the profile root, so
	// refuse the ones that were never meant for the sandbox.
	return grants.RefuseHomeFiles(s)
}
