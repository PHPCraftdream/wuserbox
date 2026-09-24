// Package setup owns the life of a sandbox: creating it, running commands in
// it, and removing it, together with the rights those need.
package setup

import (
	"flag"
	"os"
	"strings"
	"syscall"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
)

// repeated collects a flag that may appear more than once.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, string(os.PathListSeparator)) }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

// resolveAll resolves each value of a repeated directory flag in this
// process, for the same reason --dir is resolved here rather than left to
// whatever context reads it next.
func resolveAll(dirs repeated) (repeated, error) {
	resolved := make(repeated, len(dirs))
	for i, dir := range dirs {
		r, err := paths.Resolve(dir)
		if err != nil {
			return nil, err
		}
		resolved[i] = r
	}
	return resolved, nil
}

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
	return parseOptions(name, args, callerHasTerminal)
}

func parseOptions(name string, args []string, hasTerminal func() bool) (sandbox.Options, []string, error) {
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
	// Every directory is resolved in this process rather than carried as
	// typed. A run without administrator rights hands its work to an
	// elevated copy that starts in a console and a current directory of its
	// own, and a path that only meant something against this current
	// directory would name another sandbox there -- or, where this process
	// has no current directory to mean anything against, land wherever the
	// copy defaults to. Resolved once, the spelling travels whole.
	dir, err := paths.Resolve(o.dir)
	if err != nil {
		return sandbox.Options{}, nil, err
	}
	o.dir = dir
	if o.rw, err = resolveAll(o.rw); err != nil {
		return sandbox.Options{}, nil, err
	}
	if o.ro, err = resolveAll(o.ro); err != nil {
		return sandbox.Options{}, nil, err
	}
	if o.nonInteractive {
		_ = os.Setenv(EnvNonInteractive, "1")
	}
	if o.allowLinks {
		_ = os.Setenv(acl.EnvAllowLinks, "1")
	}
	// Two answers to one question -- a console in a window of its own, or a
	// windowless one relayed through this one -- and the stub refuses the
	// environment variables together. Answering here as well says so in the
	// flags the operator actually typed, before a sandbox is built on a
	// command line that was never going to run.
	if o.ownConsole && o.consoleRelay {
		return sandbox.Options{}, nil, exit.Errorf(exit.Usage,
			"--own-console and --console-relay each give the program a different console; set only one")
	}
	if o.plainStdio && (o.ownConsole || o.consoleRelay) {
		return sandbox.Options{}, nil, exit.Errorf(exit.Usage,
			"--plain-stdio cannot be combined with --own-console or --console-relay")
	}
	if name == "run" {
		_ = os.Unsetenv(proc.EnvOwnConsole)
		_ = os.Unsetenv(proc.EnvConsoleRelay)
		switch {
		case o.ownConsole:
			_ = os.Setenv(proc.EnvOwnConsole, "1")
		case o.consoleRelay || (!o.plainStdio && hasTerminal()):
			_ = os.Setenv(proc.EnvConsoleRelay, "1")
		}
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
	ownConsole                     bool
	consoleRelay                   bool
	plainStdio                     bool
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
	if name == "run" {
		flags.BoolVar(&o.ownConsole, "own-console", false,
			"give the program a console of its own instead of sharing this one")
		flags.BoolVar(&o.consoleRelay, "console-relay", false,
			"relay the program's console through this one instead of a window of its own")
		flags.BoolVar(&o.plainStdio, "plain-stdio", false,
			"pass ordinary standard streams even when running from a terminal")
	}
	return flags, o
}

func callerHasTerminal() bool {
	return allConsoleStreams(os.Stdin, os.Stdout, os.Stderr)
}

func allConsoleStreams(stdin, stdout, stderr *os.File) bool {
	for _, stream := range []*os.File{stdin, stdout, stderr} {
		if stream == nil {
			return false
		}
		var mode uint32
		if syscall.GetConsoleMode(syscall.Handle(stream.Fd()), &mode) != nil {
			return false
		}
	}
	return true
}
