package setup

import (
	"fmt"
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
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
	for _, configuring := range configuringFlags {
		if configuring.used(options) {
			return exit.Errorf(exit.Usage,
				"--%s says what the sandbox is, not how to run it; use `%s` first",
				configuring.flag, configuring.instead)
		}
	}
	return nil
}

// configuringFlags are the flags a run knows only in order to turn down. They
// belong to init, and a run parses them so that naming one is answered with
// where it belongs rather than with "flag provided but not defined".
//
// A run's help entry therefore does not list them, and must not: they are not
// options of running. This is the one list saying so, and the test that holds
// each command's help to its flag set reads it here rather than repeating it.
var configuringFlags = []struct {
	flag    string
	instead string
	used    func(sandbox.Options) bool
}{
	{"rw", "wuserbox --add-dir <dir>", func(o sandbox.Options) bool { return len(o.RW) > 0 }},
	{"ro", "wuserbox --add-dir <dir> --ro", func(o sandbox.Options) bool { return len(o.RO) > 0 }},
	{"no-ai", "wuserbox --init --no-ai", func(o sandbox.Options) bool { return o.NoAI }},
	{"home-writes", "wuserbox --init --home-writes", func(o sandbox.Options) bool { return o.HomeWrites }},
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
			"(try `wuserbox --help` for the commands)", word)
}
