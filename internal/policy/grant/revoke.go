package grant

import (
	"github.com/PHPCraftdream/wuserbox/internal/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// Revoke removes every entry for account from path. Like Apply, it is held on
// the path: taking one account's entries away rewrites the whole list, and
// another sandbox writing at the same moment would lose its own.
func Revoke(account, path string) error {
	return lock.Hold(lock.ForPath(path), func() error {
		return acl.Remove(path, account)
	})
}
