package acl

import "wuserbox/internal/win/sid"

// Deny adds an explicit refusal for account on path. Windows checks refusals
// before permissions, so this overrides anything inherited from a parent
// directory.
func Deny(path, account string, access uint32) error {
	value, err := sid.Parse(account)
	if err != nil {
		return err
	}
	return apply(path, []explicitAccess{entry(value, access, InheritNone, denyAccess)})
}
