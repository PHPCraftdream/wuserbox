// Package access answers what a sandbox could do to a file, by asking
// Windows rather than by trying it.
package access

import "fmt"

// Operation is the thing someone wants to do to a path.
type Operation string

const (
	Read   Operation = "read"
	Write  Operation = "write"
	Create Operation = "create"
	Delete Operation = "delete"
)

// Operations lists them in the order help texts should.
var Operations = []Operation{Read, Write, Create, Delete}

// Parse turns the word from a command line into an operation.
func Parse(word string) (Operation, error) {
	for _, operation := range Operations {
		if string(operation) == word {
			return operation, nil
		}
	}
	return "", fmt.Errorf("unknown operation %q (one of read, write, create, delete)", word)
}

// mask is the access the operation needs on the object itself.
func (o Operation) mask() uint32 {
	const (
		readData       = 0x1
		writeData      = 0x2
		appendData     = 0x4
		readAttributes = 0x80
		deleteAccess   = 0x10000
		readControl    = 0x20000
		synchronize    = 0x100000
		addFile        = 0x2 // on a directory, the same bit as writeData
	)
	switch o {
	case Read:
		return readData | readAttributes | readControl | synchronize
	case Write:
		return writeData | appendData | synchronize
	case Create:
		// Putting something new in a directory needs the right to add a file
		// to it, and nothing else. Asking for more than that does not make the
		// answer stricter, it makes it wrong: a permission that allows the
		// deed would be reported as refusing it.
		//
		// Listing was measured not to matter — a directory handing out only
		// FILE_ADD_FILE takes a new file — and traversing matters even less,
		// because SeChangeNotifyPrivilege bypasses that check and a restricted
		// token keeps it: DISABLE_MAX_PRIVILEGE disables every privilege
		// except that one. Both were in this mask, and the profile root is
		// where it showed: a real Windows profile grants Everyone and
		// BUILTIN\Users nothing, so a --home-writes grant covered the deed and
		// failed the question, and --explain called a working permission
		// broken.
		//
		// SYNCHRONIZE stays. It was not needed in the measurement, but what
		// supplied it there cannot be told apart from what this machine hands
		// out on its own, and every permission wuserbox grants carries it, so
		// asking for it costs nothing and keeps the answer on the safe side.
		return addFile | synchronize
	case Delete:
		return deleteAccess
	}
	return 0
}

// onParent reports whether the question is really about the directory that
// would hold the object: creating something that does not exist yet.
func (o Operation) onParent() bool { return o == Create }

// changes reports whether the operation alters the object rather than reading
// it, which is what the read-only mark stands in the way of.
func (o Operation) changes() bool { return o == Write || o == Delete }

// DeleteChild is the right to remove something from a directory. Windows
// allows a deletion when the object itself may be deleted or when the
// directory holding it carries this, so an answer about deleting has to ask
// both questions.
const DeleteChild uint32 = 0x40
