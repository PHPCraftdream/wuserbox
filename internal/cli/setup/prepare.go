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
	if err := reconcilePreset(s, options); err != nil {
		report(options, "%v", err)
		return adjustment{rebuild: true, dropPreset: s.NoAI}, nil
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

// reconcilePreset brings the agent preset in line with the sandbox's own
// standing decision, not with the flags on this particular command line.
//
// A run never carries --no-ai: onlyRunning refuses it before options reaches
// here. What decides this is s.NoAI, set once by an explicit `init --no-ai`
// and read from every run after, so the decision means the same thing until
// something explicitly changes it, rather than lapsing the moment the flag
// stops being typed.
func reconcilePreset(s *state.State, options sandbox.Options) error {
	if s.NoAI {
		return grants.DropPreset(s)
	}
	// The sandbox is brought in line with the preset on every start, so a
	// directory the preset gained since the sandbox was built is reached, and
	// --home-writes reaches a sandbox that was built without it.
	return grants.ApplyPreset(s, options.HomeWrites)
}

func rebuild(options sandbox.Options, name string) (*state.State, error) {
	existing, err := state.Load(name)
	if err != nil {
		return nil, err
	}
	if err := Elevate(rebuildOptions(options, existing).Args()); err != nil {
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

// rebuildOptions is what actually goes into the elevated re-exec.
//
// A run can never carry --no-ai; onlyRunning refuses it before options
// reaches here. So when the group is missing or broken and has to be built
// again, a record already on disk is the only place that decision survives.
// Without folding it back in, the elevated init would read the run's own
// silence as "presets are wanted again" and hand the agent preset back to a
// sandbox it was explicitly taken from.
func rebuildOptions(options sandbox.Options, existing *state.State) sandbox.Options {
	if existing != nil && existing.NoAI {
		options.NoAI = true
	}
	return options
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

// previewInput is what Preview works its plan out from. A sandbox that
// already exists decides its own NoAI and carries grants — a --grant given
// once, say — that nothing else on this command line would reproduce. Built
// only from this invocation's flags, a preview would show the agent preset a
// saved --no-ai withheld, and leave out what --grant recorded nowhere else.
func previewInput(options sandbox.Options, group, dir string, existing *state.State) plan.Input {
	in := plan.Input{
		Group: group, Dir: dir, Temp: filepath.Join(paths.StateDir(), "tmp", group),
		RW: options.RW, RO: options.RO,
		NoAI: options.NoAI, HomeWrites: options.HomeWrites,
	}
	if existing != nil {
		in.Temp = existing.Temp
		in.NoAI = existing.NoAI
		in.Existing = existing.Grants
	}
	return in
}

// Preview prints what a sandbox would be given, and changes nothing. It is
// what --dry-run reaches for on init and run.
func Preview(options sandbox.Options) error {
	group, dir, err := sandbox.Name(options.Dir)
	if err != nil {
		return err
	}
	existing, _ := state.Load(group)
	prepared, err := plan.For(previewInput(options, group, dir, existing))
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
