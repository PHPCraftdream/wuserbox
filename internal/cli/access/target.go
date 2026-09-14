// Package access hands directories to a sandbox and takes them back, either
// for one project or as a standing rule.
package access

import (
	"flag"
	"io"
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/cli/setup"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/plan"
)

// target is the "<dir> [--ro] [--dir project]" shape these commands share.
type target struct {
	path    string
	project string
	kind    grant.Kind
	dryRun  bool
	asJSON  bool
}

// readOnlyApplies reports whether a command does anything with --ro. Handing a
// directory over can be narrowed to reading; taking one back cannot.
//
// Registering the flag on all four meant "wuserbox --revoke <dir> --ro" was
// accepted and then ignored: a flag that reads as though it narrows what is
// withdrawn, and withdraws everything anyway. The help never listed it there,
// which is how it went unnoticed.
func readOnlyApplies(command string) bool { return command == "grant" || command == "add-dir" }

// targetOptions are the flags the directory commands read.
type targetOptions struct {
	readOnly       bool
	dir            string
	dryRun         bool
	asJSON         bool
	nonInteractive bool
}

// targetFlags builds the flag set for one of them.
//
// It stands apart from the parsing so that a test can walk the flags a command
// really takes and hold the help to exactly those. A manual that lists a flag
// the command does not have, or leaves out one it does, misleads more than
// having no manual at all.
func targetFlags(name string) (*flag.FlagSet, *targetOptions) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	usage.Quiet(flags)
	o := &targetOptions{}
	if readOnlyApplies(name) {
		flags.BoolVar(&o.readOnly, "ro", false, "read-only")
	}
	flags.StringVar(&o.dir, "dir", "", "project directory")
	flags.BoolVar(&o.dryRun, "dry-run", false, "show what would change, change nothing")
	flags.BoolVar(&o.asJSON, "json", false, "print the result as JSON")
	flags.BoolVar(&o.nonInteractive, "non-interactive", false,
		"fail instead of asking for administrator rights")
	return flags, o
}

// parseTarget reads that shape. The directory may be written in any usual
// form; it is resolved to a real path here.
func parseTarget(name string, args []string) (target, error) {
	flags, o := targetFlags(name)
	// The directory may be written before or after the options, so the two
	// are separated here: the flag package would stop at the first of them.
	options, operands := split(args)
	if err := flags.Parse(options); err != nil {
		return target{}, exit.Errorf(exit.Usage, "%v", err)
	}
	if len(operands) != 1 {
		readOnly := ""
		if readOnlyApplies(name) {
			readOnly = "[--ro] "
		}
		return target{}, exit.Errorf(exit.Usage,
			"usage: wuserbox --%s <dir> %s[--dir project] [--dry-run] [--json]", name, readOnly)
	}
	path, err := paths.Resolve(operands[0])
	if err != nil {
		return target{}, err
	}
	project := o.dir
	if project == "" {
		if project, err = os.Getwd(); err != nil {
			return target{}, err
		}
	}
	_, project, err = sandbox.Name(project)
	if err != nil {
		return target{}, err
	}
	if o.nonInteractive {
		_ = os.Setenv(setup.EnvNonInteractive, "1")
	}
	kind := grant.RW
	if o.readOnly {
		kind = grant.RO
	}
	return target{path: path, project: project, kind: kind, dryRun: o.dryRun, asJSON: o.asJSON}, nil
}

// args rebuilds the command line, for a second attempt with more rights or for
// the command this one goes on to call.
//
// Every flag that decides what the answer looks like travels with it. Dropping
// --json here meant add-dir handed the work to grant, which then wrote prose
// where the caller had asked for one JSON document.
//
// command is given bare ("grant", "revoke"); the dash that tells a command
// from a program is added here, once, so a caller that re-executes this line
// through elevation is never left running it as a program by that name.
func (t target) args(command string) []string {
	out := []string{"--" + command, t.path, "--dir", t.project}
	// Only where the command reads it. A rebuilt "--revoke <dir> --ro" would
	// now be rejected outright rather than ignored, which is how an elevated
	// second attempt would fail for a reason nobody could see.
	if t.kind == grant.RO && readOnlyApplies(command) {
		out = append(out, "--ro")
	}
	if t.asJSON {
		out = append(out, "--json")
	}
	return out
}

// load returns the bookkeeping of an initialized sandbox.
func load(project string) (*state.State, error) {
	name, _, err := sandbox.Name(project)
	if err != nil {
		return nil, err
	}
	s, err := state.Load(name)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, exit.Errorf(exit.NotFound,
			"no sandbox for %s yet; run `wuserbox --init` there", project)
	}
	return s, nil
}

// split separates option arguments from plain ones, so their order on the
// command line does not matter.
func split(args []string) (options, operands []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			operands = append(operands, arg)
			continue
		}
		options = append(options, arg)
		// --dir takes a value, unless it was written as --dir=value.
		if strings.TrimLeft(arg, "-") == "dir" && i+1 < len(args) {
			i++
			options = append(options, args[i])
		}
	}
	return options, operands
}

// preview prints the changes a command would make and returns without making
// them.
func (t target) preview(actions ...plan.Action) error {
	text, err := plan.RenderActions(actions, t.asJSON)
	if err != nil {
		return err
	}
	_, _ = io.WriteString(os.Stdout, text)
	return nil
}
