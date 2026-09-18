package grants

import (
	"os"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// readGroupWait keeps a second first-start from looking hung behind a
// provisioning run that stopped while ACLs were being propagated through a
// large home directory. The operation remains serialized and fail-closed;
// only the wait is bounded.
const readGroupWait = 10 * time.Second

// EnsureReadGroup makes the profile of whoever is running this readable to
// the read group belonging to them, which is the one identity a sandbox can
// reach that profile through: neither Everyone nor BUILTIN\Users covers a
// Windows profile, which by default names only its owner, the system and
// administrators.
//
// One group per person, not one for the machine. A single shared group was
// safe while a sandbox was the caller's own token cut down -- the first of
// the two access checks still had to pass as the person the caller really
// was, and nobody was a member of a group with no members. It stopped being
// safe the moment a sandbox became an account that joins the group for real:
// on a machine with two people, one person's sandbox could read the other's
// profile, private keys among it, because both profiles granted that one
// group.
//
// What it asks is whether the permission is on the profile, not whether the
// group exists. Those are two different things, and the second is a poor
// stand-in for the first: the group is created before the permission is
// applied, so a run stopped in between would leave the group behind as proof
// of work never done, and no later run would put it right.
//
// Creating the group needs administrator rights, the same as creating a
// sandbox's own group, so it piggybacks on the elevation init already needs.
// Granting a profile does not: its owner may do that themselves, which is why
// the two are asked separately.
func EnsureReadGroup() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	owner, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	if err := ensureReadable(group.ReadGroupFor(owner), home); err != nil {
		return err
	}
	return dropLegacyReadGroup(home)
}

// dropLegacyReadGroup takes the machine-wide read group's permission off
// this profile.
//
// Leaving it would leave the hole open on exactly the machines that already
// have it: a profile granted to a group that every sandbox on the machine
// belongs to, including sandboxes belonging to somebody else. The group
// itself is left alone -- another person's profile may still grant it until
// their own init runs, and deleting it under them would cost them reads they
// still rely on rather than protect anybody.
func dropLegacyReadGroup(home string) error {
	legacy, exists := resolve(group.LegacyReadGroup)
	if !exists {
		return nil // never existed on this machine, so nothing granted it
	}
	return lock.Hold(group.LegacyReadGroup, func() error {
		if !acl.Reads(home, legacy.String()) {
			return nil
		}
		return acl.Remove(home, legacy.String())
	})
}

// ensureReadable is the whole of it, with the two machine-wide names handed in
// rather than reached for.
//
// They are parameters so the mechanism can be exercised at all. Reaching for
// the real group and the real profile directly left both halves of this
// untestable: the branch that creates the group never ran anywhere the group
// already existed, which is every machine that had run wuserbox once, and the
// branch that grants a profile could only be tried by granting the profile of
// whoever was running the tests.
func ensureReadable(name, home string) error {
	return lock.HoldWait(name, readGroupWait, func() error {
		account, err := sid.Lookup(name)
		if err != nil {
			if err := group.Add(name, "wuserbox: reads a profile from inside a sandbox"); err != nil {
				return err
			}
			if account, err = sid.Lookup(name); err != nil {
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

// resolve is sid.Lookup where not finding the name is an answer rather than
// a failure: a group that was never created is the ordinary case here.
func resolve(name string) (sid.Value, bool) {
	value, err := sid.Lookup(name)
	return value, err == nil
}
