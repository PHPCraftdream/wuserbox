package token

import "wuserbox/internal/win/w32"

var procIsUserAnAdmin = w32.Shell32.NewProc("IsUserAnAdmin")

// IsAdmin reports whether this process runs elevated.
func IsAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}
