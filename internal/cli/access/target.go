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

// parseTarget reads that shape. The directory may be written in any usual
// form; it is resolved to a real path here.
func parseTarget(name string, args []string) (target, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	usage.Quiet(flags)
	readOnly := flags.Bool("ro", false, "read-only")
	dir := flags.String("dir", "", "project directory")
	dryRun := flags.Bool("dry-run", false, "show what would change, change nothing")
	asJSON := flags.Bool("json", false, "print the result as JSON")
	nonInteractive := flags.Bool("non-interactive", false,
		"fail instead of asking for administrator rights")
	// The directory may be written before or after the options, so the two
	// are separated here: the flag package would stop at the first of them.
	options, operands := split(args)
	if err := flags.Parse(options); err != nil {
		return target{}, exit.Errorf(exit.Usage, "%v", err)
	}
	if len(operands) != 1 {
		return target{}, exit.Errorf(exit.Usage,
			"usage: wuserbox %s <dir> [--ro] [--dir project] [--dry-run] [--json]", name)
	}
	path, err := paths.Resolve(operands[0])
	if err != nil {
		return target{}, err
	}
	project := *dir
	if project == "" {
		if project, err = os.Getwd(); err != nil {
			return target{}, err
		}
	}
	_, project, err = sandbox.Name(project)
	if err != nil {
		return target{}, err
	}
	if *nonInteractive {
		_ = os.Setenv(setup.EnvNonInteractive, "1")
	}
	kind := grant.RW
	if *readOnly {
		kind = grant.RO
	}
	return target{path: path, project: project, kind: kind, dryRun: *dryRun, asJSON: *asJSON}, nil
}

// args rebuilds the command line, for a second attempt with more rights or for
// the command this one goes on to call.
//
// Every flag that decides what the answer looks like travels with it. Dropping
// --json here meant add-dir handed the work to grant, which then wrote prose
// where the caller had asked for one JSON document.
func (t target) args(command string) []string {
	out := []string{command, t.path, "--dir", t.project}
	if t.kind == grant.RO {
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
			"no sandbox for %s yet; run `wuserbox init` there", project)
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
