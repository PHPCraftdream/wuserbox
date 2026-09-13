package grant

import "github.com/PHPCraftdream/wuserbox/internal/win/acl"

// Revoke removes every entry for account from path.
func Revoke(account, path string) error {
	return acl.Remove(path, account)
}
