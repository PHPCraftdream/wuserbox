package grants

import (
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// EnsureReadGroup creates group.ReadGroup and grants it read-and-execute on
// the user's profile root, the one place a fully restricted token cannot
// reach through Everyone or BUILTIN\Users. It runs on every init, but the
// comment left on the group is what makes every call after the first free:
// once it is there, the profile tree is never walked again.
//
// Creating the group needs administrator rights, the same as creating a
// sandbox's own group — this piggybacks on that elevation rather than asking
// for a separate one.
func EnsureReadGroup() error {
	return lock.Hold(group.ReadGroup, func() error {
		if _, exists, err := group.Comment(group.ReadGroup); err != nil {
			return err
		} else if exists {
			return nil
		}
		if err := group.Add(group.ReadGroup, "wuserbox: reads every sandbox's profile"); err != nil {
			return err
		}
		account, err := sid.Lookup(group.ReadGroup)
		if err != nil {
			return err
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		entries := []acl.ACE{
			{Access: acl.AccessReadExecute, Inheritance: acl.InheritObjects | acl.InheritContainers},
		}
		return acl.Set(home, account.String(), entries)
	})
}
