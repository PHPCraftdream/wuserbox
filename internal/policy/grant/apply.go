package grant

import (
	"fmt"

	"wuserbox/internal/win/acl"
)

// Apply gives account the access described by kind on path. Applying the same
// grant twice is harmless: the entries are replaced, not duplicated.
func Apply(account, path string, kind Kind) error {
	entries := kind.Entries()
	if len(entries) == 0 {
		return fmt.Errorf("unknown grant kind %q", kind)
	}
	return acl.Set(path, account, entries)
}
