package grants

import (
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// EnsureReadGroup makes the profile of whoever is running this readable to
// group.ReadGroup, the one identifier a fully restricted token can reach the
// profile through: neither Everyone nor BUILTIN\Users covers a Windows
// profile, which by default names only its owner, the system and
// administrators.
//
// What it asks is whether the permission is on the profile, not whether the
// group exists. Those are two different things, and the second is a poor
// stand-in for the first: the group is machine-wide and is created before the
// permission is applied, so a run stopped in between would leave the group
// behind as proof of work never done, and no later run would put it right.
// The same mistake hides the second person on a shared machine entirely --
// the group already exists, so their own profile would never be reached.
//
// Creating the group needs administrator rights, the same as creating a
// sandbox's own group, so it piggybacks on the elevation init already needs.
// Granting a profile does not: its owner may do that themselves, which is why
// the two are asked separately.
func EnsureReadGroup() error {
	return lock.Hold(group.ReadGroup, func() error {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		account, err := sid.Lookup(group.ReadGroup)
		if err != nil {
			if err := group.Add(group.ReadGroup, "wuserbox: reads a profile from inside a sandbox"); err != nil {
				return err
			}
			if account, err = sid.Lookup(group.ReadGroup); err != nil {
				return err
			}
		}
		if acl.Reads(home, account.String()) {
			return nil
		}
		return acl.Set(home, account.String(), []acl.ACE{
			{Access: acl.AccessReadExecute, Inheritance: acl.InheritObjects | acl.InheritContainers},
		})
	})
}
