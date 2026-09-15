// Package cli turns command-line arguments into sandbox operations.
package cli

import (
	"io"
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/cli/access"
	"github.com/PHPCraftdream/wuserbox/internal/cli/diagnose"
	"github.com/PHPCraftdream/wuserbox/internal/cli/inspect"
	"github.com/PHPCraftdream/wuserbox/internal/cli/setup"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// command is one entry in the dispatch table.
type command struct {
	run        func([]string) error
	privileged bool // may change permissions, so it is barred inside a sandbox
}

var commands = map[string]command{
	"run":        {run: setup.Run},
	"init":       {run: setup.Init, privileged: true},
	"rm":         {run: setup.Rm, privileged: true},
	"grant":      {run: access.Grant, privileged: true},
	"revoke":     {run: access.Revoke, privileged: true},
	"add-dir":    {run: access.AddDir, privileged: true},
	"remove-dir": {run: access.RemoveDir, privileged: true},
	"name":       {run: inspect.Name},
	"path":       {run: inspect.Path},
	"list":       {run: inspect.List},
	"audit":      {run: inspect.Audit},
	"version":    {run: inspect.Version},
	"explain":    {run: diagnose.Explain},
	"check":      {run: diagnose.Check},
	"config":     {run: diagnose.Config},
}

// aliases accept the spellings people reach for out of habit. They carry the
// dash too: without one, a word is a program.
var aliases = map[string]string{
	"--add_dir": "add-dir", "--remove_dir": "remove-dir",
}

// commandFor reads one word as a command, and says whether it is one.
//
// The dash is what tells a command from a program: "wuserbox --list" asks
// wuserbox, "wuserbox list" starts a program called list. Nothing without a
// dash is a command, so a program is never shadowed by one, and a new command
// can be added without changing what an existing command line means.
func commandFor(word string) (string, bool) {
	if canonical, known := aliases[word]; known {
		return canonical, true
	}
	name, dashed := strings.CutPrefix(word, "--")
	if !dashed {
		return "", false
	}
	if _, known := commands[name]; known {
		return name, true
	}
	return "", false
}

// Execute dispatches one command. Arguments exclude the program name.
func Execute(args []string) error {
	if len(args) == 0 {
		_, _ = io.WriteString(os.Stderr, usage.Text)
		return exit.Errorf(exit.Usage, "no command given")
	}
	if isHelpRequest(args[0]) {
		return help(args[1:])
	}
	name, isCommand := commandFor(args[0])
	cmd := commands[name]
	if !isCommand {
		// Anything that is not a command is a program to run in the sandbox
		// of the current directory, so `wuserbox notepad.exe` is all it takes.
		// Options are told apart by their leading dash and come first;
		// everything from the program onwards belongs to the program.
		return setup.Run(args)
	}
	rest := args[1:]
	if asksForHelp(rest) {
		return help([]string{name})
	}
	// Sandboxed code must not be able to widen its own permissions. The check
	// reads the kernel's restricted-token flag, which it cannot clear.
	if cmd.privileged && token.IsRestricted() {
		return exit.Errorf(exit.Denied, "refusing to run %q from inside a sandbox: "+
			"a sandboxed process may not change its own permissions", name)
	}
	return cmd.run(rest)
}

// isHelpRequest reports whether word is one of the two spellings that ask for
// help at the front of the command line. "help" without a dash is not one of
// them: nothing without a dash is a command, and that includes this one, so
// it is read as a program like any other.
func isHelpRequest(word string) bool {
	return word == "-h" || word == "--help"
}

// help prints the overview, or the full entry for one command.
func help(args []string) error {
	switch len(args) {
	case 0:
		_, _ = io.WriteString(os.Stdout, usage.Text)
		return nil
	case 1:
		// The whole manual, for a reader with nothing else to hand. It carries
		// a dash like everything else that asks wuserbox something, so the bare
		// word stays free: "wuserbox --help all" still reports that there is no
		// command called all, rather than quietly printing this instead.
		if args[0] == "--all" {
			_, _ = io.WriteString(os.Stdout, usage.Full())
			return nil
		}
		name, isCommand := commandFor(args[0])
		if !isCommand {
			name = args[0]
		}
		detail, known := usage.Detail(name)
		if !known {
			return exit.Errorf(exit.NotFound, "no command named %q (try `wuserbox --help` for the list)", args[0])
		}
		_, _ = io.WriteString(os.Stdout, detail)
		return nil
	default:
		return exit.Errorf(exit.Usage, "usage: wuserbox --help [command]")
	}
}

// asksForHelp reports whether the arguments contain a request for help. Only
// the part before "--" counts: after it, the flags belong to the command being
// run rather than to wuserbox.
//
// Only the flags count, never the bare word. A directory may be called help,
// and `wuserbox --add-dir help --dir <project>` used to print the help text,
// change nothing and report success: a command that looked as though it had
// done its work. Asking still works, but only with a dash, at the front,
// where `wuserbox --help add-dir` is answered before any command sees its
// arguments.
func asksForHelp(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}
