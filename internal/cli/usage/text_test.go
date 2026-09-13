package usage

import (
	"strings"
	"testing"
)

func TestEveryCommandIsDocumented(t *testing.T) {
	commands := []string{
		"run", "init", "grant", "revoke", "add-dir", "remove-dir",
		"name", "path", "list", "rm", "audit",
	}
	for _, command := range commands {
		if !strings.Contains(Text, "wuserbox "+command) {
			t.Errorf("the help text does not mention %q", command)
		}
	}
}

func TestEveryOptionIsDocumented(t *testing.T) {
	for _, option := range []string{"--dir", "--rw", "--ro", "--no-ai", "--home-writes"} {
		if !strings.Contains(Text, option) {
			t.Errorf("the help text does not mention %q", option)
		}
	}
}

func TestTextEndsWithANewline(t *testing.T) {
	if !strings.HasSuffix(Text, "\n") {
		t.Error("the help text should end with a newline")
	}
}
