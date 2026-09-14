// Package cli turns command-line arguments into sandbox operations.
package cli

import (
	"io"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/cli/access"
	"github.com/PHPCraftdream/wuserbox/internal/cli/diagnose"
	"github.com/PHPCraftdream/wuserbox/internal/cli/inspect"
	"github.com/PHPCraftdream/wuserbox/internal/cli/setup"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/exit"
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

// aliases accept the spellings people reach for out of habit.
var aliases = map[string]string{
	"add_dir": "add-dir", "--add-dir": "add-dir", "--add_dir": "add-dir",
	"remove_dir": "remove-dir", "--remove-dir": "remove-dir", "--remove_dir": "remove-dir",
}

// Execute dispatches one command. Arguments exclude the program name.
func Execute(args []string) error {
	if len(args) == 0 {
		_, _ = io.WriteString(os.Stderr, usage.Text)
		return exit.Errorf(exit.Usage, "no command given")
	}
	name := resolve(args[0])
	switch name {
	case "help", "-h", "--help":
		return help(args[1:])
	}
	cmd, known := commands[name]
	if !known {
		return exit.Errorf(exit.Usage, "unknown command %q (try `wuserbox help`)", args[0])
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

// help prints the overview, or the full entry for one command.
func help(args []string) error {
	switch len(args) {
	case 0:
		_, _ = io.WriteString(os.Stdout, usage.Text)
		return nil
	case 1:
		name := resolve(args[0])
		detail, known := usage.Detail(name)
		if !known {
			return exit.Errorf(exit.NotFound, "no command named %q (try `wuserbox help` for the list)", args[0])
		}
		_, _ = io.WriteString(os.Stdout, detail)
		return nil
	default:
		return exit.Errorf(exit.Usage, "usage: wuserbox help [command]")
	}
}

// resolve maps an alias to the command it stands for.
func resolve(name string) string {
	if canonical, ok := aliases[name]; ok {
		return canonical
	}
	return name
}

// asksForHelp reports whether the arguments contain a request for help. Only
// the part before "--" counts: after it, the flags belong to the command being
// run rather than to wuserbox.
//
// Only the flags count, never the bare word. A directory may be called help,
// and `wuserbox add-dir help --dir <project>` used to print the help text,
// change nothing and report success: a command that looked as though it had
// done its work. The word is still a way to ask, but at the front, where
// `wuserbox help add-dir` is answered before any command sees its arguments.
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
