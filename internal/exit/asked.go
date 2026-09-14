package exit

import "strings"

// JSONAsked reports whether the command line asks for JSON.
//
// It is read from the arguments rather than from the command that parsed them,
// because a failure can happen before any of them is parsed: an unknown
// command, a missing value, a flag nobody recognizes. Those are exactly the
// failures a script most needs to read.
//
// Only the part before "--" counts. After it the flags belong to the program
// being run in the sandbox, and its --json is not a request made of wuserbox.
func JSONAsked(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		name, value, hasValue := strings.Cut(arg, "=")
		if name != "--json" && name != "-json" {
			continue
		}
		if !hasValue {
			return true
		}
		return value != "false" && value != "0"
	}
	return false
}
