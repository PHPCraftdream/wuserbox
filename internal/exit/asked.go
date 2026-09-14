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
//
// The last --json on the line decides, not the first: that is how the flag
// package itself resolves a flag given more than once, and reading this any
// other way answers a repeated or overridden --json differently from how it
// was actually going to be parsed.
func JSONAsked(args []string) bool {
	asked := false
	for _, arg := range args {
		if arg == "--" {
			break
		}
		name, value, hasValue := strings.Cut(arg, "=")
		if name != "--json" && name != "-json" {
			continue
		}
		if !hasValue {
			asked = true
			continue
		}
		asked = value != "false" && value != "0"
	}
	return asked
}
