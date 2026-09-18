package grant

import (
	"fmt"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// Apply gives account the access described by kind on path, and takes
// Everyone and BUILTIN\Users' write access to that same reach away, whatever
// gave it to them.
//
// Applying the same grant twice is harmless: the entries are replaced, not
// duplicated. Every kind goes through the same isolating update, read-only
// ones included: a sandbox's own restricted list carries Everyone and Users
// so it can read the system it needs to run anything, so any directory whose
// tree happens to carry a write grant for either of them is writable by every
// sandbox that holds it, not only the one this call is for.
//
// The change is held on the path itself, not on the sandbox asking for it. Two
// sandboxes handed the same shared directory each read its whole access list,
// alter a copy and write the lot back, and without this one of the two
// permissions is lost while its record still claims it. It is held on the
// whole tree, because that is what is changed: the sweep reaches everything
// under the path, so a grant on a directory inside this one is the same change
// under another name.
// pinned is the record's own paths for this account, passed straight through
// to Isolate: the sweep it runs needs it to tell an object the operator
// pinned in its own right from one a sandbox only made to look that way
// (internal/win/acl/owner.go).
func Apply(account, path string, kind Kind, pinned []string) error {
	entries := kind.Entries()
	if len(entries) == 0 {
		return fmt.Errorf("unknown grant kind %q", kind)
	}
	return lock.HoldTree(path, func() error {
		return acl.Isolate(path, account, entries, kind.IsolationReach(), pinned)
	})
}
