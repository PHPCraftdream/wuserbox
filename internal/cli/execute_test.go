package cli

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
)

func TestUnknownCommandIsReported(t *testing.T) {
	err := Execute([]string{"frobnicate"})
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("got %v", err)
	}
}

func TestNoArgumentsIsReported(t *testing.T) {
	if err := Execute(nil); err == nil {
		t.Error("expected an error")
	}
}

func TestHelpSucceeds(t *testing.T) {
	for _, spelling := range []string{"help", "-h", "--help"} {
		if err := Execute([]string{spelling}); err != nil {
			t.Errorf("%s: %v", spelling, err)
		}
	}
}

func TestAliasesReachTheSameCommand(t *testing.T) {
	for alias, want := range aliases {
		if _, ok := commands[want]; !ok {
			t.Errorf("alias %q points at %q, which is not a command", alias, want)
		}
	}
}

func TestPermissionChangingCommandsAreMarked(t *testing.T) {
	// Anything that edits permissions or groups has to be barred inside a
	// sandbox; forgetting the mark is the mistake this catches.
	mustBePrivileged := []string{"init", "rm", "grant", "revoke", "add-dir", "remove-dir"}
	for _, name := range mustBePrivileged {
		if !commands[name].privileged {
			t.Errorf("%q is not marked as changing permissions", name)
		}
	}
	for _, name := range []string{"run", "name", "path", "list", "audit", "version"} {
		if commands[name].privileged {
			t.Errorf("%q should be usable inside a sandbox", name)
		}
	}
}

func TestEveryCommandHasAnImplementation(t *testing.T) {
	for name, command := range commands {
		if command.run == nil {
			t.Errorf("%q has no implementation", name)
		}
	}
}

func TestDispatcherAndHelpListTheSameCommands(t *testing.T) {
	documented := map[string]bool{}
	for _, entry := range usage.Commands {
		documented[entry.Name] = true
		if _, known := commands[entry.Name]; !known {
			t.Errorf("the help documents %q, which the dispatcher does not accept", entry.Name)
		}
	}
	for name := range commands {
		if !documented[name] {
			t.Errorf("the dispatcher accepts %q, which the help says nothing about", name)
		}
	}
}

func TestHelpMarksTheSameCommandsAsPrivileged(t *testing.T) {
	for _, entry := range usage.Commands {
		if got := commands[entry.Name].privileged; got != entry.Privileged {
			t.Errorf("%q is privileged=%v in the dispatcher and %v in the help",
				entry.Name, got, entry.Privileged)
		}
	}
}

func TestHelpForOneCommandSucceeds(t *testing.T) {
	for _, entry := range usage.Commands {
		if err := Execute([]string{"help", entry.Name}); err != nil {
			t.Errorf("help %s: %v", entry.Name, err)
		}
	}
}

func TestHelpResolvesAliases(t *testing.T) {
	if err := Execute([]string{"help", "--add_dir"}); err != nil {
		t.Errorf("an alias was not resolved: %v", err)
	}
}

func TestHelpRejectsAnUnknownCommand(t *testing.T) {
	err := Execute([]string{"help", "frobnicate"})
	if err == nil || !strings.Contains(err.Error(), "no command named") {
		t.Errorf("got %v", err)
	}
	if err := Execute([]string{"help", "run", "extra"}); err == nil {
		t.Error("two arguments should have been rejected")
	}
}

func TestAFlagAsksForTheCommandsOwnEntry(t *testing.T) {
	// Asking a command for help must not run it, and must not be treated as a
	// permission change, so it works inside a sandbox too.
	for _, args := range [][]string{
		{"--grant", "--help"},
		{"--grant", "-h"},
		{"--rm", "--help"},
		{"--run", "-h"},
	} {
		if err := Execute(args); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestHelpAfterTheSeparatorBelongsToTheCommand(t *testing.T) {
	// `wuserbox run -- git --help` asks git for help, not wuserbox.
	if asksForHelp([]string{"--", "git", "--help"}) {
		t.Error("a flag after the separator was taken for wuserbox")
	}
	if !asksForHelp([]string{"--rw", `C:\extra`, "--help", "--", "git"}) {
		t.Error("a flag before the separator was missed")
	}
}

// TestAPathNamedHelpIsNotARequestForHelp is the regression guard for a word
// that was read as a question wherever it appeared. `wuserbox add-dir help
// --dir <project>` printed the help text, changed nothing and reported
// success, so a command that had done none of its work looked as though it had.
func TestAPathNamedHelpIsNotARequestForHelp(t *testing.T) {
	for _, args := range [][]string{
		{"help", "--dir", `C:\project`},
		{"--dir", `C:\project`, "help"},
		{"--dir", "help"},
	} {
		if asksForHelp(args) {
			t.Errorf("%v was read as a request for help", args)
		}
	}
}

// TestTheHelpFlagsStillAsk keeps the ways of asking that a person actually
// uses, and keeps the line at "--": after it the flags belong to the program
// being run in the sandbox.
func TestTheHelpFlagsStillAsk(t *testing.T) {
	for _, args := range [][]string{
		{"-h"}, {"--help"}, {`C:\tools`, "--help"}, {"--dir", `C:\p`, "-h"},
	} {
		if !asksForHelp(args) {
			t.Errorf("%v asks for help", args)
		}
	}
	if asksForHelp([]string{"--", "node", "--help"}) {
		t.Error("a flag after -- belongs to the command being run")
	}
}

// TestHelpForACommandIsStillReachable covers the way the word still works:
// at the front, where it is dispatched before any command sees its arguments.
func TestHelpForACommandIsStillReachable(t *testing.T) {
	if err := Execute([]string{"help", "add-dir"}); err != nil {
		t.Errorf("`wuserbox help add-dir` failed: %v", err)
	}
	if err := Execute([]string{"--add-dir", "--help"}); err != nil {
		t.Errorf("`wuserbox --add-dir --help` failed: %v", err)
	}
}

// TestBareCommandWordsAreNeverCommands is the contract a dash exists to give:
// a program is never shadowed by a wuserbox command that happens to share its
// name, because nothing without a dash is read as a command at all.
func TestBareCommandWordsAreNeverCommands(t *testing.T) {
	for name := range commands {
		if _, isCommand := commandFor(name); isCommand {
			t.Errorf("the bare word %q was read as a command", name)
		}
		if _, isCommand := commandFor("--" + name); !isCommand {
			t.Errorf("the dashed word %q was not read as a command", "--"+name)
		}
	}
}

// TestARunWithNoCommandFallsThroughToTheProgram covers the other side of the
// same contract by going through the whole dispatcher: a bare word that
// matches no command is a program, so trying to run it reports a missing
// program rather than dispatching to anything wuserbox understands.
func TestARunWithNoCommandFallsThroughToTheProgram(t *testing.T) {
	err := Execute([]string{"grant"})
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("the bare word \"grant\" should have been read as a program: %v", err)
	}
}

// TestExplicitDashedRunReachesTheProgramAfterTheSeparator is the regression
// guard for the one spelling meant to disambiguate a program that shares a
// name with a command. "wuserbox run -- list" (bare "run") was documented as
// working and did not: the bare word was never a command, so it was read as
// the name of the program to run, with "list" folded in as its own argument.
// "wuserbox --run -- list" is the spelling that actually works, because the
// dash is what puts "run" through the dispatcher at all.
func TestExplicitDashedRunReachesTheProgramAfterTheSeparator(t *testing.T) {
	err := Execute([]string{"--run", "--", "no-such-program-wuserbox-xyz"})
	if err == nil || !strings.Contains(err.Error(), "no-such-program-wuserbox-xyz") {
		t.Errorf("the program after -- was not what failed: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "\"--run\"") {
		t.Errorf("--run itself was treated as the missing program: %v", err)
	}
}
