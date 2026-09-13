package exec

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// CommandLine resolves argv[0] against PATH and turns the arguments into the
// single string CreateProcessAsUser expects.
//
// Batch files cannot be started directly, so they go through the command
// interpreter, and that changes the quoting rules: the interpreter reads the
// line first and treats `&`, `|`, `<`, `>` and friends as its own punctuation.
// An argument such as `a&whoami` would otherwise become a second command.
func CommandLine(args []string) (string, error) {
	executable, err := exec.LookPath(args[0])
	if err != nil {
		return "", err
	}
	if absolute, err := filepath.Abs(executable); err == nil {
		executable = absolute
	}
	parts := append([]string{executable}, args[1:]...)

	switch strings.ToLower(filepath.Ext(executable)) {
	case ".cmd", ".bat":
		return interpreterLine(parts)
	}
	quoted := make([]string, len(parts))
	for i, part := range parts {
		quoted[i] = syscall.EscapeArg(part)
	}
	return strings.Join(quoted, " "), nil
}

// interpreterLine builds `cmd.exe /s /c "..."`. With /s the interpreter strips
// the outer pair of quotes and takes the rest as it stands, and every argument
// inside is quoted, so its punctuation is data rather than syntax.
//
// An argument holding a quote of its own is refused. There is no spelling that
// carries a literal quote through the interpreter into a batch parameter:
// doubling it, escaping it with a backslash and escaping it with a caret were
// each tried against a real script, and each arrived as something other than
// what was passed. Saying so is better than handing the script a different
// argument and letting it fail somewhere further on.
func interpreterLine(parts []string) (string, error) {
	quoted := make([]string, len(parts))
	for i, part := range parts {
		if strings.Contains(part, `"`) {
			return "", fmt.Errorf("the argument %q holds a quote, and a batch file cannot receive one: "+
				"call the program directly instead of through %s, or pass the value another way",
				part, filepath.Base(parts[0]))
		}
		quoted[i] = quoteForInterpreter(part)
	}
	return `cmd.exe /s /c "` + strings.Join(quoted, " ") + `"`, nil
}

// quoteForInterpreter wraps an argument in quotes, always, so the interpreter
// reads its punctuation as text. Arguments holding a quote never reach it.
//
// One thing quoting cannot stop is variable expansion: the interpreter
// replaces %NAME% before the script runs, and there is no escape for it on a
// command line. An argument that names a variable therefore arrives expanded,
// the same way it would from any other Windows program that calls a batch
// file.
func quoteForInterpreter(arg string) string {
	return `"` + arg + `"`
}
