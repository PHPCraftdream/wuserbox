package token

import (
	"syscall"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var procIsTokenRestricted = w32.Advapi32.NewProc("IsTokenRestricted")

// IsRestricted reports whether this process already runs inside a sandbox.
// The kernel owns the flag, so sandboxed code cannot clear it by editing its
// environment or its arguments.
func IsRestricted() bool {
	var self syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_QUERY, &self); err != nil {
		return false
	}
	defer self.Close()
	r, _, _ := procIsTokenRestricted.Call(uintptr(self))
	return r != 0
}
