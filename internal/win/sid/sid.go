// Package sid resolves and formats Windows security identifiers.
package sid

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procLookupAccountName                   = w32.Advapi32.NewProc("LookupAccountNameW")
	procLookupAccountSid                    = w32.Advapi32.NewProc("LookupAccountSidW")
	procConvertSidToStringSid textConverter = w32.Advapi32.NewProc("ConvertSidToStringSidW")
)

// textConverter is the one call this package makes of Windows to turn an
// identifier into text, behind an interface so the refusal tests can stand
// in for it: no account on any machine produces a real refusal on demand,
// and a stubbed converter does. syscall.LazyProc's Call has exactly this
// shape, so the proc itself satisfies it and the production value is the
// real thing still.
type textConverter interface {
	Call(a ...uintptr) (r1, r2 uintptr, lastErr error)
}

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

// String renders the identifier in S-1-5-… form. The value itself crosses to
// the formatter and is the owner it holds: the bytes stay alive until Windows
// is done reading them, not merely until the address &v[0] became a number.
// A refused conversion comes back as the same empty string an empty Value
// gives -- String has no error to hand up -- and the fallible callers that
// need the reason ask format directly.
func (v Value) String() string {
	if len(v) == 0 {
		return ""
	}
	text, err := format(unsafe.Pointer(&v[0]), v)
	if err != nil {
		return ""
	}
	return text
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

// format renders the identifier Windows keeps at pointer, the reason a
// conversion failed included. pointer travels typed, and owner -- the Go
// memory the identifier lives in -- travels beside it, because a uintptr
// holds nothing down: the buffer a caller read the identifier from can be
// collected the moment nothing points at it any more, and the allocations
// this call makes on the way are exactly where the compiler stops keeping
// it. The conversion to a number happens in the call expression itself, the
// shape the unsafe rules demand for memory a system call reads, and the
// KeepAlive after it holds precisely that owner until the answer is back.
func format(pointer unsafe.Pointer, owner []byte) (string, error) {
	var text *uint16
	r, _, callErr := procConvertSidToStringSid.Call(uintptr(pointer), uintptr(unsafe.Pointer(&text)))
	runtime.KeepAlive(owner)
	if r == 0 {
		return "", fmt.Errorf("formatting the identifier: %w", callErr)
	}
	defer w32.Free(uintptr(unsafe.Pointer(text)))
	return w32.GoString(text), nil
}
