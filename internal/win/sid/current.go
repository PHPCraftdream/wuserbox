package sid

import (
	"errors"
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

	// Two calls, the shape GetTokenInformation requires: the first names
	// the size and is refused by design, so only some other refusal is a
	// real failure, and a size of zero is refused too rather than indexed
	// into as an empty slice.
	var size uint32
	err := syscall.GetTokenInformation(token, syscall.TokenUser, nil, 0, &size)
	if err != nil && !errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) {
		return "", fmt.Errorf("sizing the token user: %w", err)
	}
	if size == 0 {
		return "", errors.New("the token reports no size for its user")
	}
	buf := make([]byte, size)
	if err := syscall.GetTokenInformation(token, syscall.TokenUser, &buf[0], size, &size); err != nil {
		return "", fmt.Errorf("reading the token user: %w", err)
	}
	return format(*(*uintptr)(unsafe.Pointer(&buf[0]))), nil
}
