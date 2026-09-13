package usage

import (
	"strings"
	"testing"
)

func TestEveryCommandIsInTheOverview(t *testing.T) {
	for _, command := range Commands {
		if !strings.Contains(Text, "wuserbox "+command.Name) {
			t.Errorf("the overview does not mention %q", command.Name)
		}
		if !strings.Contains(Text, command.Summary) {
			t.Errorf("the overview does not carry the summary of %q", command.Name)
		}
	}
}

func TestOverviewTellsAnAgentWhatToAskFor(t *testing.T) {
	// The first reader is usually a program that has just been refused a
	// write, so the overview has to say what the boundary is and who can
	// lift it.
	for _, phrase := range []string{
		"Access is denied",
		"wuserbox add-dir",
		"NOT inside the",
		"WUSERBOX_DIR",
		"refuse to run from inside a",
		`Run "wuserbox help <command>"`,
	} {
		if !strings.Contains(Text, phrase) {
			t.Errorf("the overview does not mention %q", phrase)
		}
	}
}

func TestOverviewExplainsHowLongExtraDirectoriesLast(t *testing.T) {
	if !strings.Contains(Text, "stay in force for later runs") {
		t.Error("the overview does not say how long --rw and --ro last")
	}
}

func TestOverviewEndsWithANewline(t *testing.T) {
	if !strings.HasSuffix(Text, "\n") {
		t.Error("the overview should end with a newline")
	}
}

func TestEveryEntryIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, command := range Commands {
		if seen[command.Name] {
			t.Errorf("%q is listed twice", command.Name)
		}
		seen[command.Name] = true

		if command.Summary == "" || command.Call == "" || command.Detail == "" {
			t.Errorf("%q is missing a summary, a call or a description", command.Name)
		}
		if len(command.Examples) == 0 {
			t.Errorf("%q has no example", command.Name)
		}
		if !strings.HasPrefix(command.Call, command.Name) {
			t.Errorf("the call of %q starts with %q", command.Name, command.Call)
		}
		for _, example := range command.Examples {
			if !strings.HasPrefix(example, "wuserbox "+command.Name) {
				t.Errorf("%q has an example for another command: %q", command.Name, example)
			}
		}
	}
}

func TestEveryOptionIsExplainedAndShownInTheCall(t *testing.T) {
	for _, command := range Commands {
		rendered, _ := Detail(command.Name)
		for _, option := range command.Options {
			flag := strings.Fields(option.Name)[0]
			if option.Effect == "" {
				t.Errorf("%q says nothing about %s", command.Name, flag)
			}
			if !strings.Contains(rendered, flag) {
				t.Errorf("the entry for %q does not show %s", command.Name, flag)
			}
			if !strings.Contains(command.Call, "[") && !strings.Contains(command.Call, "options") {
				t.Errorf("the call of %q hides that it takes %s", command.Name, flag)
			}
		}
	}
}

func TestDetailRendersTheWholeEntry(t *testing.T) {
	rendered, known := Detail("run")
	if !known {
		t.Fatal("run has no entry")
	}
	for _, heading := range []string{"USAGE", "DESCRIPTION", "OPTIONS", "EXAMPLES"} {
		if !strings.Contains(rendered, heading) {
			t.Errorf("the entry for run has no %s section", heading)
		}
	}
	if !strings.Contains(rendered, "wuserbox run [options] -- <command>") {
		t.Errorf("the entry for run does not show how to call it:\n%s", rendered)
	}
}

func TestDetailWarnsAboutElevationAndAboutTheSandbox(t *testing.T) {
	elevating, _ := Detail("init")
	if !strings.Contains(elevating, "administrator rights") {
		t.Error("the entry for init does not mention the consent prompt")
	}
	restricted, _ := Detail("grant")
	if !strings.Contains(restricted, "Refuses to run inside a sandbox") {
		t.Error("the entry for grant does not say it is barred inside a sandbox")
	}
	plain, _ := Detail("version")
	if strings.Contains(plain, "NOTES") {
		t.Error("a command with nothing to warn about should have no notes")
	}
}

func TestDetailReportsAnUnknownCommand(t *testing.T) {
	if _, known := Detail("frobnicate"); known {
		t.Error("an unknown command was reported as documented")
	}
}
