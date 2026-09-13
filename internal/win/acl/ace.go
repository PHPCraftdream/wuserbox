// Package acl reads and writes the permissions on files and directories.
package acl

// ACE is one access control entry: what is allowed, and how it is inherited.
type ACE struct {
	Access      uint32
	Inheritance uint32
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
	AccessCreateFiles uint32 = 0x10008B
)

// Write bits, used when judging whether a permission is dangerous.
const writeMask = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000000 | 0x10000000
