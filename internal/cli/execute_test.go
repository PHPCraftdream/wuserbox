package cli

import (
	"strings"
	"testing"
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
