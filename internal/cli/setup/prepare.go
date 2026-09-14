package setup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/lock"
	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/grants"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/plan"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// adjustment is what bringing an existing sandbox in line with the flags came
// to. Rebuilding is reported rather than done, because it starts a second
// wuserbox with administrator rights and that one waits for the same lock.
type adjustment struct {
	state *state.State
	// rebuild says the sandbox has to be created again by an elevated run.
	rebuild bool
	// dropPreset says --no-ai still has to reach the rebuilt sandbox.
	dropPreset bool
}

// prepare loads the sandbox, building or repairing it with administrator
// rights when the group is missing or a permission cannot be applied as the
// plain user.
func prepare(options sandbox.Options) (*state.State, error) {
	name, _, err := sandbox.Name(options.Dir)
	if err != nil {
		return nil, err
	}
	var made adjustment
	// Reading the record and changing permissions is one operation, so it is
	// done with the record held. Elevation is deliberately left outside.
	if err := lock.Hold(name, func() error {
		var err error
		made, err = adjust(options, name)
		return err
	}); err != nil {
		return nil, err
	}
	if !made.rebuild {
		return made.state, nil
	}
	repaired, err := rebuild(options, name)
	if err != nil {
		return nil, err
	}
	if !made.dropPreset {
		return repaired, nil
	}
	return repaired, lock.Hold(name, func() error {
		if err := grants.DropPreset(repaired); err != nil {
			return fmt.Errorf("--no-ai could not take back the agent directories: %w", err)
		}
		return nil
	})
}

// missing reports whether the sandbox has to be created before anything can be
// adjusted: either nothing was ever recorded, or the group the record names is
// no longer there. Neither is an error to pass on; both are a reason to build
// it again with administrator rights.
func missing(name string, s *state.State) bool {
	if s == nil {
		return true
	}
	_, err := sid.Lookup(name)
	return err != nil
}

// adjust brings an existing sandbox in line with the flags, with the record
// already held. It changes permissions and never starts another process.
func adjust(options sandbox.Options, name string) (adjustment, error) {
	s, err := state.Load(name)
	if err != nil {
		return adjustment{}, err
	}
	if missing(name, s) {
		report(options, "creating sandbox %s", name)
		return adjustment{rebuild: true}, nil
	}
	// A command that was stopped between writing a change down and applying it
	// left the record ahead of the file system. Nothing else here would notice,
	// because everything else trusts the record.
	if err := s.FinishPending(); err != nil {
		report(options, "%v", err)
		return adjustment{rebuild: true}, nil
	}
	if options.NoAI {
		// The flag has to mean the same thing on every run, not only on the
		// one that created the sandbox. If the permissions cannot be taken
		// back, the command must not start: running it anyway would hand it
		// the very directories that were just refused.
		if err := grants.DropPreset(s); err != nil {
			report(options, "%v", err)
			return adjustment{rebuild: true, dropPreset: true}, nil
		}
	}
	if !options.NoAI {
		// The sandbox is brought in line with the flags on every start, so a
		// plain run after one with --no-ai gets the agent directories back,
		// and --home-writes reaches a sandbox that was built without it.
		if err := grants.ApplyPreset(s, options.HomeWrites); err != nil {
			report(options, "%v", err)
			return adjustment{rebuild: true}, nil
		}
	}
	if err := grants.FromConfig(s, false); err != nil {
		report(options, "%v", err)
		return adjustment{rebuild: true}, nil
	}
	if err := grants.Extra(s, options.RW, options.RO, false); err != nil {
		report(options, "%v", err)
		return adjustment{rebuild: true}, nil
	}
	return adjustment{state: s}, nil
}

func rebuild(options sandbox.Options, name string) (*state.State, error) {
	if err := Elevate(options.Args()); err != nil {
		return nil, err
	}
	s, err := state.Load(name)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("sandbox %s was not created", name)
	}
	return s, nil
}

// report prints a progress message, unless the caller asked for quiet. These
// go to the error stream: the output stream belongs to the command being run.
func report(options sandbox.Options, format string, args ...any) {
	// Silent under --json as well as under --quiet. A command asked for JSON
	// answers with one document, and a line of prose before it leaves the
	// stream unparseable for exactly the reader that asked.
	if options.Quiet || options.JSON {
		return
	}
	fmt.Fprintf(os.Stderr, "wuserbox: "+format+"\n", args...)
}

// Preview prints what a sandbox would be given, and changes nothing. It is
// what --dry-run reaches for on init and run.
func Preview(options sandbox.Options) error {
	group, dir, err := sandbox.Name(options.Dir)
	if err != nil {
		return err
	}
	temp := filepath.Join(paths.StateDir(), "tmp", group)
	if existing, err := state.Load(group); err == nil && existing != nil {
		temp = existing.Temp
	}
	prepared, err := plan.For(plan.Input{
		Group: group, Dir: dir, Temp: temp,
		RW: options.RW, RO: options.RO,
		NoAI: options.NoAI, HomeWrites: options.HomeWrites,
	})
	if err != nil {
		return err
	}
	text, err := plan.Render(prepared, options.JSON)
	if err != nil {
		return err
	}
	_, _ = io.WriteString(os.Stdout, text)
	return nil
}
