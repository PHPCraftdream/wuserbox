package sid

// Identifiers Windows assigns the same value on every machine.
const (
	// Everyone has to be a restricting identifier on the sandbox token:
	// starting any program that loads the window subsystem opens
	// \Sessions\N\Windows, whose permissions name only Everyone. Without it
	// every process except the command interpreter dies with 0xC0000142.
	Everyone = "S-1-1-0"
	System   = "S-1-5-18"
)
