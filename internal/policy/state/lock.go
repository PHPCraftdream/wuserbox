package state

import "github.com/PHPCraftdream/wuserbox/internal/lock"

// RulesLock is the name to hold while the standing rules are read, changed and
// written back.
const RulesLock = lock.Rules

// Locked runs work with a sandbox's record held for the caller alone, waiting
// for whoever holds it now.
//
// Reading the record, changing permissions and writing it back is one
// operation, and it has to be one operation to the rest of the machine as
// well. Two commands that each read the record, each hand over a different
// directory and each write back leave both permissions in force while the
// record remembers only the second: explain does not mention the first and
// revoke cannot find it.
//
// Nothing inside work may start another wuserbox for the same sandbox, because
// that one waits for this lock.
func Locked(group string, work func() error) error {
	return lock.Hold(group, work)
}
