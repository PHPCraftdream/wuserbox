package usage

import (
	"flag"
	"io"
)

// Quiet stops a flag set from reporting anything by itself.
//
// The failure it would print travels back as an error instead, carrying the
// same message, and one place decides how a failure is shown: as a line of
// prose, or as JSON when the command line asked for JSON. Left to itself the
// parser writes prose and the usage text first, and a command called with
// --json then answers with prose followed by a JSON document.
//
// The help text is not lost by this. A request for help is answered before the
// arguments reach a parser at all.
func Quiet(flags *flag.FlagSet) {
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
}
