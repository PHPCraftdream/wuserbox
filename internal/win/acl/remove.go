package acl

import "github.com/PHPCraftdream/wuserbox/internal/win/sid"

// Remove drops every entry for account from the permissions of path,
// permissions and refusals alike. Replacing is what does that: revoking
// removes only the permissions.
func Remove(path, account string) error {
	value, err := sid.Parse(account)
	if err != nil {
		return err
	}
	return apply(path, []explicitAccess{entry(value, 0, InheritNone, setAccess)}, 0)
}
