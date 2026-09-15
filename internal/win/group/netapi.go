// Package group manages the local groups that carry sandbox identity. One
// group per project directory; its comment stores the directory path, so the
// mapping needs no external database.
package group

import (
	"fmt"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// Prefix marks groups owned by wuserbox.
const Prefix = "wub-"

// ReadGroup is the one group shared by every sandbox, rather than made fresh
// per project. BUILTIN\Users covers System32 and Program Files, but nothing
// built in covers the user's own profile the same way -- a Windows profile
// names its owner, the system and administrators and nobody else -- so this
// is granted read-and-execute there once, machine-wide, and every sandbox
// account joins it.
const ReadGroup = Prefix + "read"

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
