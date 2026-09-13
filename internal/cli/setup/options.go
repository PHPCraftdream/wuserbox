// Package setup owns the life of a sandbox: creating it, running commands in
// it, and removing it, together with the rights those need.
package setup

import (
	"flag"
	"io"
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
)

// repeated collects a flag that may appear more than once.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, string(os.PathListSeparator)) }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

// ParseOptions reads the options shared by init and run. Everything after "--"
// is returned separately as the command to execute.
func ParseOptions(name string, args []string) (sandbox.Options, []string, error) {
	var command []string
	for i, a := range args {
		if a == "--" {
			command = args[i+1:]
			args = args[:i]
			break
		}
	}
	var rw, ro repeated
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { _, _ = io.WriteString(os.Stderr, usage.Text) }
	dir := flags.String("dir", "", "project directory")
	noAI := flags.Bool("no-ai", false, "skip the preset for AI agent directories")
	homeWrites := flags.Bool("home-writes", false, "let the sandbox create files in the profile root")
	quiet := flags.Bool("quiet", false, "no progress messages, errors only")
	nonInteractive := flags.Bool("non-interactive", false, "fail instead of asking for administrator rights")
	dryRun := flags.Bool("dry-run", false, "show what would change, change nothing")
	asJSON := flags.Bool("json", false, "print the result as JSON")
	flags.Var(&rw, "rw", "extra writable directory")
	flags.Var(&ro, "ro", "extra readable directory")
	if err := flags.Parse(args); err != nil {
		return sandbox.Options{}, nil, err
	}
	if *dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return sandbox.Options{}, nil, err
		}
		*dir = cwd
	}
	if *nonInteractive {
		_ = os.Setenv(EnvNonInteractive, "1")
	}
	options := sandbox.Options{
		Dir: *dir, RW: rw, RO: ro,
		NoAI: *noAI, HomeWrites: *homeWrites, Quiet: *quiet,
		DryRun: *dryRun, JSON: *asJSON,
	}
	return options, append(flags.Args(), command...), nil
}
