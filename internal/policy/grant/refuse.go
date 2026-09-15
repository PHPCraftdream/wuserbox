package grant

import (
	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// Refuse blocks account from changing path, whatever a parent directory
// allows. Refusals are checked before permissions, so this survives a
// permission that reaches the file through inheritance.
//
// It refuses changing and not reading, which is the whole of the difference
// between AccessChange and AccessModify. Refusing with the wider mask looks
// stricter and is simply wrong: the wider one carries FILE_READ_DATA and
// READ_CONTROL, and a restricted token's second check refuses the entire
// request the moment any bit still wanted is denied, so the file stopped being
// readable as well. That is what --home-writes does to every file already in
// the profile root, which left the sandbox unable to read ~/.gitconfig or
// ~/.npmrc -- against the promise this tool opens with.
//
// Held on the tree, like every other change to an access list.
func Refuse(account, path string) error {
	return lock.HoldTree(path, func() error {
		return acl.Deny(path, account, acl.AccessChange)
	})
}
