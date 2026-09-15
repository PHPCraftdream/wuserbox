// Package setup owns the life of a sandbox: creating it, running commands in
// it, and removing it, together with the rights those need.
package setup

import (
	"flag"
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// repeated collects a flag that may appear more than once.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, string(os.PathListSeparator)) }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

// ParseOptions reads the options shared by init and run. Everything from the
// program onwards — including any "--" of its own — is returned separately as
// the command to execute.
//
// There is no separate pass looking for "--": flag.Parse already stops at the
// first argument that is not one of wuserbox's own flags, and leaves
// everything from there on, unexamined, in Args(). A "--" only ends wuserbox's
// own flags when it is the thing parsing reaches first, which is exactly the
// explicit "wuserbox --run -- list" spelling. One that turns up later, inside
// the program's own arguments — "wuserbox git checkout -- file.txt" — is never
// looked at, so it reaches the program exactly as typed.
func ParseOptions(name string, args []string) (sandbox.Options, []string, error) {
	flags, o := sharedFlags(name)
	if err := flags.Parse(args); err != nil {
		return sandbox.Options{}, nil, exit.Errorf(exit.Usage, "%v", err)
	}
	if o.dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return sandbox.Options{}, nil, err
		}
		o.dir = cwd
	}
	if o.nonInteractive {
		_ = os.Setenv(EnvNonInteractive, "1")
	}
	if o.allowLinks {
		_ = os.Setenv(acl.EnvAllowLinks, "1")
	}
	options := sandbox.Options{
		Dir: o.dir, RW: o.rw, RO: o.ro,
		NoAI: o.noAI, HomeWrites: o.homeWrites, Quiet: o.quiet,
		DryRun: o.dryRun, JSON: o.asJSON, AllowLinks: o.allowLinks,
	}
	return options, flags.Args(), nil
}

// shared is every flag init and run read.
type shared struct {
	rw, ro                         repeated
	dir                            string
	noAI, homeWrites, quiet        bool
	nonInteractive, dryRun, asJSON bool
	allowLinks                     bool
}

// sharedFlags builds that set. It stands apart from the parsing so a test can
// walk the flags a command really takes and hold the help to exactly those.
func sharedFlags(name string) (*flag.FlagSet, *shared) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	usage.Quiet(flags)
	o := &shared{}
	flags.StringVar(&o.dir, "dir", "", "project directory")
	flags.BoolVar(&o.noAI, "no-ai", false, "skip the preset for AI agent directories")
	flags.BoolVar(&o.homeWrites, "home-writes", false, "let the sandbox create files in the profile root")
	flags.BoolVar(&o.quiet, "quiet", false, "no progress messages, errors only")
	flags.BoolVar(&o.nonInteractive, "non-interactive", false, "fail instead of asking for administrator rights")
	flags.BoolVar(&o.dryRun, "dry-run", false, "show what would change, change nothing")
	flags.BoolVar(&o.asJSON, "json", false, "print the result as JSON")
	flags.BoolVar(&o.allowLinks, "allow-links", false,
		"hand a directory over even where a file in it has another name elsewhere")
	flags.Var(&o.rw, "rw", "extra writable directory")
	flags.Var(&o.ro, "ro", "extra readable directory")
	return flags, o
}
