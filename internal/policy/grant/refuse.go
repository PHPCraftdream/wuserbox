package grant

import "wuserbox/internal/win/acl"

// Refuse blocks account from changing path, whatever a parent directory
// allows. Refusals are checked before permissions, so this survives a
// permission that reaches the file through inheritance.
func Refuse(account, path string) error {
	return acl.Deny(path, account, acl.AccessModify)
}
