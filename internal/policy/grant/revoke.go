package grant

import (
	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// Revoke takes account's access off path and everything under it, capping
// what the owner of an object account itself owns holds implicitly -- a
// revoke used to leave that WRITE_DAC standing, because acl.Remove only ever
// rewrote path itself (internal/win/acl/reclaim.go). Like Apply, it is held
// on the tree: taking one account's entries away rewrites the whole list,
// and another sandbox writing at the same moment would lose its own.
//
// pinned is the record's own paths for this account, passed straight through
// to TakeBack: a directory this same account holds in its own right, granted
// separately, is left alone rather than taken down with the tree above it.
//
// The account is handed over as the group that exists, the same way Apply
// hands it over: any lookup about it that falls short stops the revoke
// before the walk starts.
func Revoke(account, path string, pinned []string) error {
	return lock.HoldTree(path, func() error {
		return acl.TakeBack(path, identityOf(account), pinned)
	})
}
