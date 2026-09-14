package setup

import (
	"fmt"
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/exec"
)

// Run starts a command in the sandbox, creating the sandbox on first use, and
// ends this process with the command's own exit code.
//
// This is what wuserbox does when the first word is not one of its commands,
// so `wuserbox notepad.exe` needs nothing else.
func Run(args []string) error {
	options, command, err := ParseOptions("run", args)
	if err != nil {
		return err
	}
	if err := onlyRunning(options); err != nil {
		return err
	}
	if len(command) == 0 {
		return exit.Errorf(exit.Usage, "no command given: wuserbox [options] <program> [arguments...]")
	}
	commandLine, err := exec.CommandLine(command)
	if err != nil {
		return notAProgram(command[0], err)
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

// onlyRunning refuses the options that describe what a sandbox is, rather than
// how this one run behaves.
//
// Starting a program takes the sandbox as it stands and changes nothing. What
// it may write is decided before, and in one place, so that the answer does not
// depend on which command line happened to start it: a directory handed over by
// a flag on one run and forgotten on the next is a sandbox nobody can reason
// about.
func onlyRunning(options sandbox.Options) error {
	for _, configuring := range []struct {
		used    bool
		flag    string
		instead string
	}{
		{len(options.RW) > 0, "--rw", "wuserbox add-dir <dir>"},
		{len(options.RO) > 0, "--ro", "wuserbox add-dir <dir> --ro"},
		{options.NoAI, "--no-ai", "wuserbox init --no-ai"},
		{options.HomeWrites, "--home-writes", "wuserbox init --home-writes"},
	} {
		if configuring.used {
			return exit.Errorf(exit.Usage,
				"%s says what the sandbox is, not how to run it; use `%s` first",
				configuring.flag, configuring.instead)
		}
	}
	return nil
}

// notAProgram explains a first word that is neither a command nor anything
// that can be started.
//
// A word with no directory separator and no extension is far more likely to be
// a mistyped command than a program: saying that it is not on the PATH would
// answer a question nobody asked.
func notAProgram(word string, cause error) error {
	if strings.ContainsAny(word, `\/.`) {
		return cause
	}
	return exit.Errorf(exit.Usage,
		"unknown command %q, and no program by that name is on your PATH "+
			"(try `wuserbox help` for the commands)", word)
}
