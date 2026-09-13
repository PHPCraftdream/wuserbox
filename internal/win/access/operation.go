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
		readData        = 0x1
		writeData       = 0x2
		appendData      = 0x4
		readAttributes  = 0x80
		deleteAccess    = 0x10000
		readControl     = 0x20000
		synchronize     = 0x100000
		addFile         = 0x2 // on a directory, the same bit as writeData
		listDirectory   = 0x1
		traverseExecute = 0x20
	)
	switch o {
	case Read:
		return readData | readAttributes | readControl | synchronize
	case Write:
		return writeData | appendData | synchronize
	case Create:
		return addFile | listDirectory | traverseExecute | synchronize
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
