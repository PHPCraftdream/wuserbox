package grant

import (
	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// Revoke removes every entry for account from path. Like Apply, it is held on
// the tree: taking one account's entries away rewrites the whole list, and
// another sandbox writing at the same moment would lose its own.
func Revoke(account, path string) error {
	return lock.HoldTree(path, func() error {
		return acl.Remove(path, account)
	})
}
