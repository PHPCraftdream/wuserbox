package setup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/grants"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/plan"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// prepare loads the sandbox, building or repairing it with administrator
// rights when the group is missing or a permission cannot be applied as the
// plain user.
func prepare(options sandbox.Options) (*state.State, error) {
	name, _, err := sandbox.Name(options.Dir)
	if err != nil {
		return nil, err
	}
	s, err := state.Load(name)
	if err != nil {
		return nil, err
	}
	if _, lookupErr := sid.Lookup(name); s == nil || lookupErr != nil {
		report(options, "creating sandbox %s", name)
		return rebuild(options, name)
	}
	if options.NoAI {
		// The flag has to mean the same thing on every run, not only on the
		// one that created the sandbox. If the permissions cannot be taken
		// back, the command must not start: running it anyway would hand it
		// the very directories that were just refused.
		if err := grants.DropPreset(s); err != nil {
			report(options, "%v", err)
			repaired, repairErr := rebuild(options, name)
			if repairErr != nil {
				return nil, repairErr
			}
			if err := grants.DropPreset(repaired); err != nil {
				return nil, fmt.Errorf("--no-ai could not take back the agent directories: %w", err)
			}
			s = repaired
		}
	}
	if !options.NoAI {
		// The sandbox is brought in line with the flags on every start, so a
		// plain run after one with --no-ai gets the agent directories back,
		// and --home-writes reaches a sandbox that was built without it.
		if err := grants.ApplyPreset(s, options.HomeWrites); err != nil {
			report(options, "%v", err)
			return rebuild(options, name)
		}
	}
	if err := grants.FromConfig(s, false); err != nil {
		report(options, "%v", err)
		return rebuild(options, name)
	}
	if err := grants.Extra(s, options.RW, options.RO, false); err != nil {
		report(options, "%v", err)
		return rebuild(options, name)
	}
	return s, nil
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
	if options.Quiet {
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
