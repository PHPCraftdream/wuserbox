package acl

import "wuserbox/internal/win/sid"

// Remove drops every entry for account from the permissions of path,
// permissions and refusals alike.
func Remove(path, account string) error {
	value, err := sid.Parse(account)
	if err != nil {
		return err
	}
	return apply(path, []explicitAccess{entry(value, 0, InheritNone, revokeAccess)})
}
