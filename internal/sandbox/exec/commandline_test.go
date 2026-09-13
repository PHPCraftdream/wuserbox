package exec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandLineResolvesAndQuotes(t *testing.T) {
	line, err := CommandLine([]string{"cmd", "/c", "echo hello world"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(line), "cmd.exe") {
		t.Errorf("the program was not resolved to a full path: %q", line)
	}
	if !strings.Contains(line, `"echo hello world"`) {
		t.Errorf("an argument with spaces was not quoted: %q", line)
	}
}

func TestCommandLineWrapsBatchFiles(t *testing.T) {
	script := writeScript(t, "@echo off\r\n")
	line, err := CommandLine([]string{script, "arg"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.ToLower(line), "cmd.exe /s /c ") {
		t.Errorf("a batch file was not handed to the interpreter: %q", line)
	}
}

func TestCommandLineReportsMissingProgram(t *testing.T) {
	if _, err := CommandLine([]string{"no-such-program-wuserbox"}); err == nil {
		t.Error("expected an error for a program that is not on PATH")
	}
}

// reporter is a batch file that writes its first argument to a file beside
// itself. It stores the argument before printing it, and prints it with
// delayed expansion, which is the only way a batch file can handle a value
// containing `&` without re-reading it as punctuation. Anything that goes
// wrong beyond that belongs to the command line wuserbox built.
const reporter = "@echo off\r\n" +
	"setlocal enabledelayedexpansion\r\n" +
	"set \"argument=%~1\"\r\n" +
	"> \"%~dp0output.txt\" echo [!argument!]\r\n"

// writeScript puts a batch file in a temporary directory and returns its path.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "script.cmd")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runBatch executes a batch file through the command line wuserbox builds and
// returns what the script wrote.
func runBatch(t *testing.T, script string, args ...string) string {
	t.Helper()
	line, err := CommandLine(append([]string{script}, args...))
	if err != nil {
		t.Fatal(err)
	}
	// The line goes to Windows exactly as the sandbox would hand it over.
	// Adding a redirection here would change how the interpreter parses it,
	// so the script writes its own output file instead.
	if err := runLine(t, line); err != nil {
		t.Logf("the command reported %v", err)
	}
	output := filepath.Join(filepath.Dir(script), "output.txt")
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("the script produced no output: %v", err)
	}
	os.Remove(output)
	return strings.TrimSpace(string(data))
}

// TestBatchArgumentsCannotStartASecondCommand is the regression guard for the
// interpreter's punctuation. Each argument below would run something of its
// own if it were read as syntax, so the test watches for the file that second
// command would leave behind, and checks that the argument reached the script
// as written.
func TestBatchArgumentsCannotStartASecondCommand(t *testing.T) {
	script := writeScript(t, reporter)
	marker := filepath.Join(filepath.Dir(script), "injected.txt")
	for _, argument := range []string{
		"a&echo PWNED>" + marker,
		"a|echo PWNED>" + marker,
		"a&&echo PWNED>" + marker,
		"a>" + marker,
		"a^&echo PWNED>" + marker,
	} {
		output := runBatch(t, script, argument)
		if _, err := os.Stat(marker); err == nil {
			os.Remove(marker)
			t.Errorf("argument %q ran a second command", argument)
		}
		if want := "[" + argument + "]"; output != want {
			t.Errorf("argument %q arrived as %q", argument, output)
		}
	}
}

func TestBatchArgumentsArriveUnchanged(t *testing.T) {
	script := writeScript(t, reporter)
	for _, argument := range []string{
		"plain",
		"with spaces",
		"a&b",
		"c^d",
		"(parens)",
		"semi;colon",
		"comma,separated",
	} {
		output := runBatch(t, script, argument)
		if want := "[" + argument + "]"; output != want {
			t.Errorf("argument %q arrived as %q", argument, output)
		}
	}
}

// TestBatchArgumentsExpandVariables records a limit rather than a guarantee.
// The interpreter replaces %NAME% on the command line before the script runs,
// and a command line has no escape for it. This is how every Windows program
// that calls a batch file behaves; the test is here so a change gets noticed.
func TestBatchArgumentsExpandVariables(t *testing.T) {
	script := writeScript(t, reporter)
	t.Setenv("WUSERBOX_MARKER", "expanded")
	if output := runBatch(t, script, "%WUSERBOX_MARKER%"); output != "[expanded]" {
		t.Logf("the interpreter left the variable alone: %q", output)
	}
}
