package setup

import (
	"fmt"
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/profile"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/exec"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/facts"
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
	if err := refuseWithoutAccount(s); err != nil {
		return err
	}
	if err := fillProfile(s); err != nil {
		return err
	}
	// Failing to write this is not a reason to refuse the run: it costs a
	// listing one accurate moment, and the run itself is what was asked for.
	if err := facts.MarkUsed(s.Group); err != nil {
		fmt.Fprintf(os.Stderr, "wuserbox: could not record this run against %s: %v\n", s.Group, err)
	}
	code, err := exec.Run(s, commandLine)
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}

// refuseWithoutAccount stops a run that would fall back to the mechanism the
// account replaced.
//
// prepare gives an account to any sandbox that lacks one, so getting here
// without it means that did not happen and nobody was told. Going ahead
// anyway is the failure worth preventing: the old mechanism still starts
// ordinary programs, so the sandbox looks fine right up until a shell -- or
// anything built on one, which is most of what gets run in here -- fails to
// start, for reasons that point nowhere near the missing account.
func refuseWithoutAccount(s *state.State) error {
	if s.Account != "" {
		return nil
	}
	return exit.Errorf(exit.Failed,
		"sandbox %s has no account of its own, and programs that need one -- a shell among them -- "+
			"will not start in it; run `wuserbox --init --dir %s` to give it one",
		s.Group, s.Dir)
}

// fillProfile puts what the rules file names into the sandbox's own profile,
// before the program starts and on every run -- unless the sandbox was told
// to skip the agent preset, in which case it takes back whatever an earlier
// run copied instead.
//
// A failure filling the profile stops the run rather than being reported and
// passed over, which is the opposite of how the timestamp above is treated,
// and for a reason: what this copies is where a program inside finds its
// credentials and settings. Missing, the program starts and then fails as
// though it were not logged in, somewhere far from here and with nothing
// pointing back.
//
// NoAI is checked here rather than left to the rules file's own list,
// because the two answer different questions. The `profile:` section says
// what to copy when copying is wanted at all; it is not asked whether a
// sandbox that already holds a copy should go on holding it after being told
// to skip the preset. Reading the rules file for that would make --no-ai
// mean nothing the moment a rules file still lists agent directories, which
// is every rules file, since that section is pre-filled with exactly that
// list.
func fillProfile(s *state.State) error {
	if s.Profile == "" {
		return nil // no profile of its own; nothing to fill
	}
	previously, err := facts.Copied(s.Group)
	if err != nil {
		return err
	}
	if s.NoAI {
		if err := profile.Clear(s.Profile, previously); err != nil {
			return err
		}
		return facts.RecordCopied(s.Group, nil)
	}
	copied, copyErr := profile.Copy(s.Profile, previously)
	// Written down whatever happened. What did land has to be findable next
	// time or nothing will ever clear it, and on a failure the union is the
	// safe reading: naming something already gone costs one attempt that
	// finds nothing, while forgetting something still there leaves it in the
	// sandbox's profile for good.
	if err := facts.RecordCopied(s.Group, union(previously, copied, copyErr != nil)); err != nil {
		return err
	}
	return copyErr
}

// union is what to record: exactly what was copied where the copy finished,
// and everything either list mentions where it did not.
func union(previously, copied []string, partial bool) []string {
	if !partial {
		return copied
	}
	seen := make(map[string]bool, len(previously)+len(copied))
	var all []string
	for _, entry := range append(append([]string{}, previously...), copied...) {
		if seen[entry] {
			continue
		}
		seen[entry] = true
		all = append(all, entry)
	}
	return all
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
