package exec

import (
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
		return interpreterLine(parts), nil
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
func interpreterLine(parts []string) string {
	quoted := make([]string, len(parts))
	for i, part := range parts {
		quoted[i] = quoteForInterpreter(part)
	}
	return `cmd.exe /s /c "` + strings.Join(quoted, " ") + `"`
}

// quoteForInterpreter wraps an argument in quotes, always, so the interpreter
// reads its punctuation as text.
//
// One thing quoting cannot stop is variable expansion: the interpreter
// replaces %NAME% before the script runs, and there is no escape for it on a
// command line. An argument that names a variable therefore arrives expanded,
// the same way it would from any other Windows program that calls a batch
// file.
func quoteForInterpreter(arg string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(arg); i++ {
		switch c := arg[i]; c {
		case '"':
			// A quote would end the quoted run; doubling it keeps it as text
			// for both the interpreter and the program's own parser.
			b.WriteString(`""`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
