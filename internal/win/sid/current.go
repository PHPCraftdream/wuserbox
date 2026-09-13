package sid

import (
	"fmt"
	"syscall"
	"unsafe"
)

// CurrentUser is the identifier of the account this process runs as. Elevation
// does not change it, so it is the same inside and outside a consent prompt.
func CurrentUser() (string, error) {
	var token syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_QUERY, &token); err != nil {
		return "", fmt.Errorf("opening the process token: %w", err)
	}
	defer token.Close()

	var size uint32
	syscall.GetTokenInformation(token, syscall.TokenUser, nil, 0, &size)
	buf := make([]byte, size)
	if err := syscall.GetTokenInformation(token, syscall.TokenUser, &buf[0], size, &size); err != nil {
		return "", fmt.Errorf("reading the token user: %w", err)
	}
	return format(*(*uintptr)(unsafe.Pointer(&buf[0]))), nil
}
