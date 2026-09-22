// Package sid resolves and formats Windows security identifiers.
package sid

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procLookupAccountName     = w32.Advapi32.NewProc("LookupAccountNameW")
	procLookupAccountSid      = w32.Advapi32.NewProc("LookupAccountSidW")
	procConvertSidToStringSid = w32.Advapi32.NewProc("ConvertSidToStringSidW")
)

// NoneMapped is the refusal LookupAccountSidW reports for an identifier no
// account or group anywhere answers to: the SID is well formed, the lookup
// ran, and nothing maps to it. It is exported because it is the one lookup
// answer that says the identifier stands alone, which is a fact a caller can
// build on; every other refusal says only that nobody knows.
const NoneMapped = syscall.Errno(1332)

// errInsufficientBuffer is the by-design refusal of a sizing call: the call
// failed, and what it failed with is the size the next call needs.
const errInsufficientBuffer = syscall.Errno(122)

// Value is a binary security identifier held in Go memory.
type Value []byte

// Lookup resolves an account name, user or group, to its identifier.
func Lookup(account string) (Value, error) {
	var sidLen, domainLen, use uint32
	procLookupAccountName.Call(0, uintptr(unsafe.Pointer(w32.UTF16(account))), 0,
		uintptr(unsafe.Pointer(&sidLen)), 0, uintptr(unsafe.Pointer(&domainLen)), uintptr(unsafe.Pointer(&use)))
	if sidLen == 0 {
		return nil, fmt.Errorf("account %q not found", account)
	}
	value := make(Value, sidLen)
	domain := make([]uint16, domainLen+1)
	r, _, err := procLookupAccountName.Call(0, uintptr(unsafe.Pointer(w32.UTF16(account))),
		uintptr(unsafe.Pointer(&value[0])), uintptr(unsafe.Pointer(&sidLen)),
		uintptr(unsafe.Pointer(&domain[0])), uintptr(unsafe.Pointer(&domainLen)), uintptr(unsafe.Pointer(&use)))
	if r == 0 {
		return nil, fmt.Errorf("looking up %q: %w", account, err)
	}
	return value, nil
}

// String renders the identifier in S-1-5-… form.
func (v Value) String() string {
	if len(v) == 0 {
		return ""
	}
	return format(uintptr(unsafe.Pointer(&v[0])))
}

// Name resolves a SID pointer back to the bare account name, without the
// domain or computer name Windows spells in front of it.
//
// It takes a raw pointer rather than a Value, because both of this
// package's own forms of SID -- the bytes Lookup fills in, and the memory
// Windows itself hands back from Parse -- already are one: a Value's is
// &v[0], Parse's is the pointer Parse returns.
//
// A caller needs this rather than a hard-coded name because a well-known
// alias is only ever spelled "Users" or "Administrators" on an
// English-language install; account.BuiltinUsersName is why this exists.
func Name(pointer uintptr) (string, error) {
	var nameLen, domainLen, use uint32
	r, _, callErr := procLookupAccountSid.Call(0, pointer, 0, uintptr(unsafe.Pointer(&nameLen)),
		0, uintptr(unsafe.Pointer(&domainLen)), uintptr(unsafe.Pointer(&use)))
	if r == 0 && !errors.Is(callErr, errInsufficientBuffer) {
		// The sizing call is refused by design; a refusal of any other kind
		// is the lookup's own answer, and it is the reason the lookup failed
		// -- a fact the caller needs, because "the domain was out of reach"
		// and "this identifier names nothing" are different decisions. It
		// used to be discarded here, and every failure came out as the same
		// not-found.
		return "", fmt.Errorf("resolving the account name: %w", callErr)
	}
	if nameLen == 0 {
		return "", errors.New("resolving the account name: the lookup named no account")
	}
	name := make([]uint16, nameLen)
	domain := make([]uint16, domainLen+1)
	r, _, err := procLookupAccountSid.Call(0, pointer, uintptr(unsafe.Pointer(&name[0])),
		uintptr(unsafe.Pointer(&nameLen)), uintptr(unsafe.Pointer(&domain[0])),
		uintptr(unsafe.Pointer(&domainLen)), uintptr(unsafe.Pointer(&use)))
	if r == 0 {
		return "", fmt.Errorf("resolving the account name: %w", err)
	}
	return syscall.UTF16ToString(name), nil
}

// format renders a SID that Windows owns.
func format(pointer uintptr) string {
	var text *uint16
	if r, _, _ := procConvertSidToStringSid.Call(pointer, uintptr(unsafe.Pointer(&text))); r == 0 {
		return ""
	}
	defer w32.Free(uintptr(unsafe.Pointer(text)))
	return w32.GoString(text)
}
