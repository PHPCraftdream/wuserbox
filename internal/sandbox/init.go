package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	// wub-read needs admin rights the same as a sandbox's own group, so this
	// piggybacks on the elevation init already needs rather than asking for a
	// separate one. Failing here does not stop the build: without it, only
	// the profile reads that depended on it are missing, the same as any
	// other grant an unprivileged run could not finish.
	if err := grants.EnsureReadGroup(); err != nil {
		note(o, "could not set up profile reads for every sandbox: %v", err)
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
	if err := grants.ProtectSettings(built); err != nil {
		return built, err
	}
	return built, nil
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

// note says what is happening, unless the caller asked for quiet or for one
// JSON document.
func note(o Options, format string, args ...any) {
	if o.Quiet || o.JSON {
		return
	}
	fmt.Fprintf(os.Stderr, "wuserbox: "+format+"\n", args...)
}

func applyPreset(s *state.State, o Options) error {
	// Set before either branch acts, so every save either branch makes along
	// the way already carries the decision: a plain run never repeats
	// --no-ai, and reads this instead of taking a fresh run's silence for
	// "presets are wanted again."
	s.NoAI = o.NoAI
	if o.NoAI {
		// Skipping is not enough for a sandbox that already holds these
		// directories: the flag has to take them back, or a later run would
		// still reach them.
		return grants.DropPreset(s)
	}
	// Together rather than one after another: each of these is a whole
	// directory tree whose files all have their permissions rewritten, and
	// they have nothing to do with one another.
	handing := preset.AI()
	note(o, "handing over %d agent directories; Windows writes the permission "+
		"into every file already in them, which is why a first run waits", len(handing))
	started := time.Now()
	if err := s.OfferMany(handing); err != nil {
		return err
	}
	note(o, "handed over in %s", time.Since(started).Round(time.Millisecond))
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
