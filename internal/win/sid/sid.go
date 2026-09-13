// Package sid resolves and formats Windows security identifiers.
package sid

import (
	"fmt"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procLookupAccountName     = w32.Advapi32.NewProc("LookupAccountNameW")
	procConvertSidToStringSid = w32.Advapi32.NewProc("ConvertSidToStringSidW")
)

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
		return nil, fmt.Errorf("looking up %q: %v", account, err)
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

// format renders a SID that Windows owns.
func format(pointer uintptr) string {
	var text *uint16
	if r, _, _ := procConvertSidToStringSid.Call(pointer, uintptr(unsafe.Pointer(&text))); r == 0 {
		return ""
	}
	defer w32.Free(uintptr(unsafe.Pointer(text)))
	return w32.GoString(text)
}
