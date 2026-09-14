package usage

import (
	"strings"
	"testing"
)

func TestEveryCommandIsInTheOverview(t *testing.T) {
	for _, command := range Commands {
		// Commands are shown with the dash that tells them from a program.
		// The default command has no name to show at all.
		shown := "wuserbox --" + command.Name
		if command.Default {
			shown = "wuserbox [options]"
		}
		if !strings.Contains(Text, shown) {
			t.Errorf("the overview does not mention %q", shown)
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
		"wuserbox --add-dir",
		"NOT inside the",
		"WUSERBOX_DIR",
		"refuse to run from inside a",
		`Run "wuserbox --help <command>"`,
	} {
		if !strings.Contains(Text, phrase) {
			t.Errorf("the overview does not mention %q", phrase)
		}
	}
}

func TestOverviewExplainsHowLongAnAllowanceLasts(t *testing.T) {
	if !strings.Contains(Text, "stays in force for later runs") {
		t.Error("the overview does not say how long an allowed directory lasts")
	}
}

// TestOverviewShowsThePlainRunFirst covers what changed about the command
// itself: running is what wuserbox does unless told otherwise, and the
// overview is read by agents that will copy the first form they see.
func TestOverviewShowsThePlainRunFirst(t *testing.T) {
	for _, phrase := range []string{
		"wuserbox [options] <program> [arguments...]",
		"Running is the default",
		"RUNNING AND CONFIGURING ARE SEPARATE",
	} {
		if !strings.Contains(Text, phrase) {
			t.Errorf("the overview does not mention %q", phrase)
		}
	}
	// And it must not go on offering the flags a run no longer takes.
	if strings.Contains(Text, "OPTIONS SHARED BY run AND init") {
		t.Error("the overview still offers configuration flags on a run")
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
		// The default command is the exception, and says so: it is reached by
		// typing no command at all, so its call and examples carry no name.
		if !command.Default && !strings.HasPrefix(command.Call, "--"+command.Name) {
			t.Errorf("the call of %q starts with %q", command.Name, command.Call)
		}
		for _, example := range command.Examples {
			if command.Default {
				if !strings.HasPrefix(example, "wuserbox ") {
					t.Errorf("%q has an example that is not a wuserbox line: %q",
						command.Name, example)
				}
				continue
			}
			if !strings.HasPrefix(example, "wuserbox --"+command.Name) {
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
	for _, heading := range []string{"USAGE", "DESCRIPTION", "OPTIONS", "EXAMPLES", "EXIT CODES"} {
		if !strings.Contains(rendered, heading) {
			t.Errorf("the entry for run has no %s section", heading)
		}
	}
	if !strings.Contains(rendered, "wuserbox [options] <program> [arguments...]") {
		t.Errorf("the entry for run does not show how to call it:\n%s", rendered)
	}
	// The explicit, dashed form still has to be findable, for anyone who
	// wants run spelled out or the -- separator shown.
	if !strings.Contains(rendered, "wuserbox --run -- list") {
		t.Errorf("the entry for run does not show the explicit form:\n%s", rendered)
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

// TestFullBeginsWithTheOverview keeps the manual usable from the top: whoever
// reads it meets the same orientation the short help gives before the entries
// start.
func TestFullBeginsWithTheOverview(t *testing.T) {
	if !strings.HasPrefix(Full(), Text) {
		t.Error("the manual does not open with the overview")
	}
	if !strings.HasSuffix(Full(), "\n") {
		t.Error("the manual should end with a newline")
	}
}

// TestFullCarriesEveryEntryWhole is what makes the manual worth printing: not a
// summary of each command but the entry itself, character for character, so
// there is nothing a reader would have to go and ask for separately.
func TestFullCarriesEveryEntryWhole(t *testing.T) {
	manual := Full()
	for _, command := range Commands {
		entry, known := Detail(command.Name)
		if !known {
			t.Errorf("%q has no entry at all", command.Name)
			continue
		}
		if !strings.Contains(manual, entry) {
			t.Errorf("the manual does not carry the entry for %q whole", command.Name)
		}
	}
}

// TestFullSeparatesTheEntries keeps one command's examples from reading as the
// next command's, which is the only way a single stream of entries misleads.
func TestFullSeparatesTheEntries(t *testing.T) {
	// One before each entry, and one more before the reference that closes it.
	if got, want := strings.Count(Full(), rule), len(Commands)+1; got != want {
		t.Errorf("the manual has %d separators, want %d", got, want)
	}
}

// TestFullCarriesWhatNothingElseSays covers the two things wuserbox knows about
// itself and never told anyone: the shape of the rules file, and the
// environment it sets and reads. They belong to the manual rather than to the
// overview, which is read by somebody who needs one answer quickly.
func TestFullCarriesWhatNothingElseSays(t *testing.T) {
	manual := Full()
	for _, phrase := range []string{
		"THE RULES FILE",
		"projects: [",
		"dir: C:/projects/app",
		"forward slashes",
		"ENVIRONMENT",
		"WUSERBOX_DIR",
		"WUSERBOX_GROUP",
		"WUSERBOX_CONFIG",
		"WUSERBOX_NON_INTERACTIVE",
		"TEMP, TMP",
	} {
		if !strings.Contains(manual, phrase) {
			t.Errorf("the manual says nothing about %q", phrase)
		}
	}
	// And the overview stays the short answer it is for.
	if strings.Contains(Text, "THE RULES FILE") {
		t.Error("the reference has moved into the overview")
	}
}

// TestEveryEntryAnswersAboutItsExitCode keeps a single entry readable on its
// own: a command with codes of its own says them, and one without says that
// too, so nobody has to guess which kind they are looking at.
func TestEveryEntryAnswersAboutItsExitCode(t *testing.T) {
	for _, command := range Commands {
		rendered, _ := Detail(command.Name)
		if !strings.Contains(rendered, "EXIT CODES") {
			t.Errorf("the entry for %q says nothing about its exit code", command.Name)
		}
		if command.Exits != "" && !strings.Contains(rendered, command.Exits) {
			t.Errorf("the entry for %q does not carry its own codes", command.Name)
		}
	}
	// The commands that answer in their exit code have to say so.
	for _, name := range []string{"run", "check", "config", "rm"} {
		entry, known := Detail(name)
		if !known {
			t.Fatalf("%q has no entry", name)
		}
		if strings.Contains(entry, "The common set, with nothing of its own") {
			t.Errorf("%q returns a code of its own, and its entry does not say which", name)
		}
	}
}

func TestDetailReportsAnUnknownCommand(t *testing.T) {
	if _, known := Detail("frobnicate"); known {
		t.Error("an unknown command was reported as documented")
	}
}
