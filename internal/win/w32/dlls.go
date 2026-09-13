// Package w32 holds the handful of things every Windows call in wuserbox
// needs: the system libraries and string conversion.
package w32

import "syscall"

// The system libraries wuserbox calls into.
var (
	Advapi32 = syscall.NewLazyDLL("advapi32.dll")
	Kernel32 = syscall.NewLazyDLL("kernel32.dll")
	Shell32  = syscall.NewLazyDLL("shell32.dll")
	Netapi32 = syscall.NewLazyDLL("netapi32.dll")
	User32   = syscall.NewLazyDLL("user32.dll")
)
