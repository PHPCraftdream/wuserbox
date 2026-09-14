package grant

import (
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
func Apply(account, path string, kind Kind) error {
	entries := kind.Entries()
	if len(entries) == 0 {
		return fmt.Errorf("unknown grant kind %q", kind)
	}
	return lock.Hold(lock.ForPath(path), func() error {
		return acl.Set(path, account, entries)
	})
}
