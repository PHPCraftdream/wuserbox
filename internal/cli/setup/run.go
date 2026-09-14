package setup

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/sandbox/exec"
)

// Run starts a command in the sandbox, creating the sandbox on first use, and
// ends this process with the command's own exit code.
func Run(args []string) error {
	options, command, err := ParseOptions("run", args)
	if err != nil {
		return err
	}
	if len(command) == 0 {
		return fmt.Errorf("no command given: wuserbox run -- <cmd> [args...]")
	}
	commandLine, err := exec.CommandLine(command)
	if err != nil {
		return err
	}
	if options.DryRun {
		if err := Preview(options); err != nil {
			return err
		}
		if !options.JSON {
			fmt.Fprintf(os.Stderr, "would run: %s\n", commandLine)
		}
		return nil
	}
	s, err := prepare(options)
	if err != nil {
		return err
	}
	code, err := exec.Run(s, commandLine)
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}
