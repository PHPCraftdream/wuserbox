package grant

import (
	"errors"
	"fmt"

	"github.com/PHPCraftdream/wuserbox/internal/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// Apply gives account the access described by kind on path. Applying the same
// grant twice is harmless: the entries are replaced, not duplicated.
//
// The change is held on the path itself, not on the sandbox asking for it. Two
// sandboxes handed the same shared directory each read its whole access list,
// alter a copy and write the lot back, and without this one of the two
// permissions is lost while its record still claims it.
// A writable permission carries a Low mandatory integrity label as well, in
// the same update. Without it a sandbox token, which runs Low, is refused its
// own writes; with it, everything that was not handed over — every path that
// keeps the ordinary Medium level — refuses the sandbox not only writing but
// deleting, which the permissions alone cannot express.
func Apply(account, path string, kind Kind) error {
	entries := kind.Entries()
	if len(entries) == 0 {
		return fmt.Errorf("unknown grant kind %q", kind)
	}
	return lock.Hold(lock.ForPath(path), func() error {
		if kind.Writable() {
			return acl.SetWritable(path, account, entries, kind.LabelInheritance())
		}
		return acl.Set(path, account, entries)
	})
}

// Applied reports whether err leaves the permission itself in force.
//
// One failure does: the entries went on and only the integrity label, which
// needs administrator rights, did not. The sandbox may write where it was
// just allowed to; what it does not yet have is the boundary that stops it
// deleting elsewhere. Callers that care about the permission use this;
// callers that care about the boundary read the sandbox's own record, which
// remembers the shortfall.
func Applied(err error) bool {
	return err == nil || errors.Is(err, acl.ErrNotLabeled)
}
