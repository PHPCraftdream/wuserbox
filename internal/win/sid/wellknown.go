package sid

// Identifiers Windows assigns the same value on every machine.
const (
	// Everyone is carried by every account there is, so a sandbox running as
	// its own account has it without asking. It still has to be named in the
	// restricting list of the token a sandbox without an account of its own
	// runs under: starting any program that loads the window subsystem opens
	// \Sessions\N\Windows, whose permissions name only Everyone, and without
	// it every process except the command interpreter dies with 0xC0000142.
	Everyone = "S-1-1-0"
	System   = "S-1-5-18"
	// Users is how a sandbox reads the system it needs in order to run
	// anything at all: Program Files and Windows itself grant Users read and
	// execute rather than Everyone. A sandbox account is made a member of it
	// outright; the older restricted token names it in its restricting list
	// instead, which arrives at the same access by a different route.
	Users = "S-1-5-32-545"
	// Authenticated Users is carried by every account that logged on, which
	// a sandbox account does on every run. It was harmless while a sandbox
	// was a restricted token, whose second check never carried it -- an entry
	// naming it reached nothing inside -- so isolation ignored it. Under an
	// account it is an ordinary membership like any other, which makes a
	// directory naming it a directory every sandbox on the machine may
	// change, whichever one it was handed to.
	Authenticated = "S-1-5-11"
	// Administrators is needed when a permission list has to be written from
	// nothing. An object with no list at all grants everybody everything,
	// administrators and the system among them, so giving it one has to name
	// them or it takes away what they had.
	Administrators = "S-1-5-32-544"
)
