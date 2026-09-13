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
	if err := Execute([]string{"help", "add_dir"}); err != nil {
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
		{"grant", "--help"},
		{"grant", "-h"},
		{"rm", "--help"},
		{"run", "-h"},
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
