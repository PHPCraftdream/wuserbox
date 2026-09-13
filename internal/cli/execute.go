// Package cli turns command-line arguments into sandbox operations.
package cli

import (
	"fmt"
	"io"
	"os"

	"wuserbox/internal/cli/access"
	"wuserbox/internal/cli/inspect"
	"wuserbox/internal/cli/launch"
	"wuserbox/internal/cli/setup"
	"wuserbox/internal/cli/usage"
	"wuserbox/internal/win/token"
)

// command is one entry in the dispatch table.
type command struct {
	run        func([]string) error
	privileged bool // may change permissions, so it is barred inside a sandbox
}

var commands = map[string]command{
	"run":        {run: launch.Run},
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
}

// aliases accept the spellings people reach for out of habit.
var aliases = map[string]string{
	"add_dir": "add-dir", "--add-dir": "add-dir", "--add_dir": "add-dir",
	"remove_dir": "remove-dir", "--remove-dir": "remove-dir", "--remove_dir": "remove-dir",
}

// Execute dispatches one command. Arguments exclude the program name.
func Execute(args []string) error {
	if len(args) == 0 {
		io.WriteString(os.Stderr, usage.Text)
		return fmt.Errorf("no command given")
	}
	name := args[0]
	if canonical, ok := aliases[name]; ok {
		name = canonical
	}
	switch name {
	case "help", "-h", "--help":
		io.WriteString(os.Stdout, usage.Text)
		return nil
	}
	cmd, ok := commands[name]
	if !ok {
		return fmt.Errorf("unknown command %q (try `wuserbox help`)", args[0])
	}
	// Sandboxed code must not be able to widen its own permissions. The check
	// reads the kernel's restricted-token flag, which it cannot clear.
	if cmd.privileged && token.IsRestricted() {
		return fmt.Errorf("refusing to run %q from inside a sandbox: "+
			"a sandboxed process may not change its own permissions", name)
	}
	return cmd.run(args[1:])
}
