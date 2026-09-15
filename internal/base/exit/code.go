// Package exit gives every way wuserbox can fail its own exit code, so a
// script can tell them apart without reading the message.
package exit

// Code is what the process returns.
type Code int

// The codes wuserbox itself returns. A command that starts another program
// is the exception: "run" returns whatever that program returned, so a script
// reading its result is reading the sandboxed command's, not wuserbox's.
const (
	// OK means the command did what was asked.
	OK Code = 0
	// Failed is any problem without a code of its own.
	Failed Code = 1
	// Usage means the command line was wrong: an unknown command, a missing
	// argument, a flag that does not exist.
	Usage Code = 2
	// Denied means the answer is no rather than the question being broken:
	// an access check that came back refused.
	Denied Code = 3
	// NeedsElevation means the operation requires administrator rights and
	// was told not to ask for them.
	NeedsElevation Code = 4
	// BadConfig means the rules file is unusable: it does not parse, or it
	// contradicts itself.
	BadConfig Code = 5
	// NotFound means what was named does not exist: an unknown group, a
	// sandbox that was never created.
	NotFound Code = 6
)

// String names the code, for help texts and messages.
func (c Code) String() string {
	switch c {
	case OK:
		return "ok"
	case Failed:
		return "failed"
	case Usage:
		return "usage"
	case Denied:
		return "denied"
	case NeedsElevation:
		return "needs-elevation"
	case BadConfig:
		return "bad-config"
	case NotFound:
		return "not-found"
	default:
		return "unknown"
	}
}
