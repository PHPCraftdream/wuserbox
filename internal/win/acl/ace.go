// Package acl reads and writes the permissions on files and directories.
package acl

// ACE is one access control entry: what it covers, how it is inherited, and
// whether it grants or refuses.
type ACE struct {
	Access      uint32
	Inheritance uint32
	// Refuse turns the entry into a refusal. Windows checks refusals first,
	// so this is the only way to hold back an access that a parent directory
	// hands down.
	Refuse bool
}

// Inheritance flags, as stored in the entry header.
const (
	InheritNone        = 0x0
	InheritObjects     = 0x1 // files inside the directory inherit
	InheritContainers  = 0x2 // subdirectories inherit
	InheritNoPropagate = 0x4 // children inherit, grandchildren do not
	InheritOnly        = 0x8 // the entry does not apply to the object itself
)

// Access masks, spelled out so no shell parsing is involved. They match the
// shorthand icacls prints.
const (
	// AccessModify is read, write, execute and delete.
	AccessModify uint32 = 0x1301BF
	// AccessReadExecute is read, list and execute.
	AccessReadExecute uint32 = 0x1200A9
	// AccessCreateFiles lists a directory and creates files in it, without
	// touching what is already there.
	//
	// It carries READ_CONTROL (0x20000) for the same reason the two above do:
	// reading an object means reading who may reach it, and a sandbox whose
	// only entry on a directory left that out could not read the directory it
	// had just been handed. That went unnoticed while every grant also handed
	// Everyone read access, which covered it from the side.
	AccessCreateFiles uint32 = 0x12008B
	// AccessChange is everything that alters an object rather than reads it:
	// writing, appending, changing attributes, and deleting it or what is
	// inside it. It is what a read-only grant has to refuse.
	//
	// This must never carry a generic bit (the top four, 0x10000000 and up).
	// Windows expands a generic bit found in an ACE's own mask to its full
	// specific-rights mapping before comparing it against what was asked for
	// -- GENERIC_WRITE (0x40000000) expands to FILE_GENERIC_WRITE, which
	// includes READ_CONTROL and SYNCHRONIZE -- so a refusal built from one
	// would deny part of an ordinary read alongside every write bit, and
	// deny it outright: a refusal naming a bit refuses every request asking
	// for it, and an ordinary read asks for READ_CONTROL. This went unseen
	// under the write-restricted token wuserbox started with, which skipped
	// its second check for reads entirely.
	AccessChange uint32 = changing &^ genericBits
)

const (
	// changing is every right that alters an object or decides who may:
	// writing and appending, the two kinds of attribute, deleting the object
	// and deleting what is inside it, rewriting its permission list, taking
	// ownership of it, and the two generic bits that stand for any of those.
	//
	// Rewriting the permission list belongs here, and its absence was a way
	// out: a sandbox left holding WRITE_DAC on a directory needs nothing else,
	// because it can hand itself everything else and then use it. Taking
	// ownership is the same story one step further back. Both were measured,
	// with a peer sandbox rewriting a list, granting Everyone full control and
	// deleting another sandbox's file.
	changing = 0x2 | // write data
		0x4 | // append data
		0x10 | // write extended attributes
		0x40 | // delete what is inside
		0x100 | // write attributes
		0x10000 | // delete
		0x40000 | // rewrite the permission list
		0x80000 | // take ownership
		genericBits
	// genericBits are the two generic rights that cover changing something.
	// They are kept out of anything written into an entry of our own, for the
	// reason spelled out on AccessChange, but they have to be recognized in
	// an entry somebody else wrote.
	genericBits = 0x40000000 | 0x10000000 // generic write, generic all
)
