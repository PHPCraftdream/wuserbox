package w32

import "syscall"

// UTF16 converts a Go string into the wide-character pointer Windows expects.
// An embedded zero byte cannot reach these calls, so the error is dropped.
func UTF16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}
