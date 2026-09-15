package grant

import (
	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// Refuse blocks account from changing path, whatever a parent directory
// allows. Refusals are checked before permissions, so this survives a
// permission that reaches the file through inheritance.
//
// Held on the tree, like every other change to an access list.
func Refuse(account, path string) error {
	return lock.HoldTree(path, func() error {
		return acl.Deny(path, account, acl.AccessModify)
	})
}
