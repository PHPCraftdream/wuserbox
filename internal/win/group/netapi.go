// Package group manages the local groups that carry sandbox identity. One
// group per project directory; its comment stores the directory path, so the
// mapping needs no external database.
package group

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// Prefix marks groups owned by wuserbox.
const Prefix = "wub-"

// ReadPrefix marks the groups that let a sandbox read a profile. One per
// person whose profile is read, not one per project: BUILTIN\Users covers
// System32 and Program Files, but nothing built in covers a user's own
// profile the same way -- a Windows profile names its owner, the system and
// administrators and nobody else.
const ReadPrefix = Prefix + "read"

// LegacyReadGroup is what that was before it was split per person: one group
// machine-wide, joined by every sandbox on it, granted read on every
// profile that had ever run init.
//
// That was safe while a sandbox was the caller's own token cut down, because
// the first of the two access checks still had to pass as the person the
// caller really was, and nobody is a member of a group with no members. It
// stopped being safe the moment a sandbox became an account that joins the
// group for real: on a machine with two people, one person's sandbox could
// read the other's profile, private keys included, since ReadGroupFor's
// predecessor was granted on both. It is named here so init can take its
// permission off a profile it still stands on.
const LegacyReadGroup = ReadPrefix

// ReadGroupFor is the group that reads the profile of the person whose
// account identifier is ownerSID. Derived rather than looked up, so nothing
// has to keep a table, and short enough to leave room inside the 256
// characters a local group name allows.
func ReadGroupFor(ownerSID string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(ownerSID)))
	return ReadPrefix + "-" + hex.EncodeToString(digest[:4])
}

const errNotFound = 2220 // NERR_GroupNotFound

var (
	procAdd     = w32.Netapi32.NewProc("NetLocalGroupAdd")
	procDel     = w32.Netapi32.NewProc("NetLocalGroupDel")
	procGetInfo = w32.Netapi32.NewProc("NetLocalGroupGetInfo")
	procEnum    = w32.Netapi32.NewProc("NetLocalGroupEnum")
	procFreeBuf = w32.Netapi32.NewProc("NetApiBufferFree")
	procSetInfo = w32.Netapi32.NewProc("NetLocalGroupSetInfo")
)

type info1 struct {
	name    *uint16
	comment *uint16
}

func status(call string, code uintptr) error {
	switch code {
	case 0:
		return nil
	case 5:
		return fmt.Errorf("%s: access denied (administrator required)", call)
	default:
		return fmt.Errorf("%s: NET_API_STATUS %d", call, code)
	}
}
