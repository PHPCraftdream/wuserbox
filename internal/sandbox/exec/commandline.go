package exec

import (
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// CommandLine resolves argv[0] against PATH and quotes the arguments into the
// single string CreateProcessAsUser expects. Batch files cannot be started
// directly, so they go through the command interpreter.
func CommandLine(args []string) (string, error) {
	exe, err := exec.LookPath(args[0])
	if err != nil {
		return "", err
	}
	if abs, err := filepath.Abs(exe); err == nil {
		exe = abs
	}
	parts := append([]string{exe}, args[1:]...)
	switch strings.ToLower(filepath.Ext(exe)) {
	case ".cmd", ".bat":
		parts = append([]string{"cmd.exe", "/c"}, parts...)
	}
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = syscall.EscapeArg(p)
	}
	return strings.Join(quoted, " "), nil
}
