package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Resolve accepts a path in any spelling a person or a shell is likely to
// produce and returns the normalized Windows form:
//
//	C:\tools  c:/tools  "C:\tools"  \\?\C:\tools
//	/c/tools        (Git Bash, MSYS)
//	/cygdrive/c/tools
//	/mnt/c/tools    (WSL)
//	~/tools  %USERPROFILE%\tools  $HOME/tools
//	../tools        (relative to the current directory)
//
// When a spelling is ambiguous every reading is tried and the one that exists
// on disk wins, so `/c/tools` finds C:\tools without guessing.
//
// A path that already names something is taken as written. A directory may
// legitimately be called project$TAG or %build%, and reading a real name as a
// variable would quietly send the caller somewhere else.
func Resolve(input string) (string, error) {
	raw := strings.TrimSpace(input)
	raw = strings.Trim(raw, `"'`)
	if raw == "" {
		return "", fmt.Errorf("empty path")
	}
	raw = strings.TrimPrefix(raw, `\\?\`)
	if found, ok := onDisk(raw); ok {
		return Normalize(found)
	}
	expanded := strings.TrimPrefix(expandVariables(raw), `\\?\`)
	if found, ok := onDisk(expanded); ok {
		return Normalize(found)
	}
	// Nothing exists yet: keep the most likely reading so the caller can
	// report a sensible error or create the directory.
	return Normalize(candidates(expanded)[0])
}

// onDisk returns the first reading of p that names something.
func onDisk(p string) (string, bool) {
	for _, candidate := range candidates(p) {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
	}
	return "", false
}

// expandVariables handles both %NAME% and $NAME spellings, plus a leading ~.
//
// A name that is not set is left alone in either spelling. Replacing it with
// nothing would turn C:\build\$STAGE into C:\build\, which is a real directory
// and the wrong one.
func expandVariables(p string) string {
	replace := func(expression *regexp.Regexp, nameOf func(string) string) {
		p = expression.ReplaceAllStringFunc(p, func(m string) string {
			if value, ok := os.LookupEnv(nameOf(m)); ok {
				return value
			}
			return m
		})
	}
	replace(percentVariable, func(m string) string { return strings.Trim(m, "%") })
	replace(shellVariable, func(m string) string {
		return strings.Trim(strings.TrimPrefix(m, "$"), "{}")
	})
	if p == "~" {
		return Home()
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(Home(), p[2:])
	}
	return p
}

var (
	percentVariable = regexp.MustCompile(`%[A-Za-z_][A-Za-z0-9_()]*%`)
	shellVariable   = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)
)

// candidates lists the readings of a path, most likely first.
func candidates(p string) []string {
	slashed := strings.ReplaceAll(p, `\`, "/")
	var out []string
	add := func(s string) {
		if s != "" {
			out = append(out, filepath.FromSlash(s))
		}
	}
	switch {
	case strings.HasPrefix(strings.ToLower(slashed), "/cygdrive/"):
		add(driveForm(slashed[len("/cygdrive/"):]))
	case strings.HasPrefix(strings.ToLower(slashed), "/mnt/"):
		add(driveForm(slashed[len("/mnt/"):]))
		add(slashed)
	case isShellDrive(slashed):
		add(driveForm(slashed[1:]))
		add(slashed)
	default:
		add(slashed)
	}
	if len(out) == 0 {
		out = append(out, filepath.FromSlash(slashed))
	}
	return out
}

// isShellDrive matches the /c or /c/... form Git Bash produces.
func isShellDrive(p string) bool {
	if len(p) < 2 || p[0] != '/' || !isLetter(p[1]) {
		return false
	}
	return len(p) == 2 || p[2] == '/'
}

// driveForm turns "c/tools" into "C:/tools".
func driveForm(p string) string {
	if p == "" || !isLetter(p[0]) {
		return ""
	}
	rest := ""
	if len(p) > 1 {
		if p[1] != '/' {
			return ""
		}
		rest = p[1:]
	}
	return strings.ToUpper(p[:1]) + ":" + rest + map[bool]string{true: "/", false: ""}[rest == ""]
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
