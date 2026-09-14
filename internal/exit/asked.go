package exit

import (
	"strconv"
	"strings"
)

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
		// Read the value the way the flag package will read it. It uses
		// strconv.ParseBool, which takes F, False and FALSE as readily as
		// false, so judging the spellings by hand answers --json=False one way
		// here and the other way there. A value it refuses is left to it to
		// refuse: the failure that follows is itself the answer, and it is
		// reported in whatever shape the last readable --json asked for.
		if wanted, err := strconv.ParseBool(value); err == nil {
			asked = wanted
		}
	}
	return asked
}
