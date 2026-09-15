package token

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var procLogonUser = w32.Advapi32.NewProc("LogonUserW")

const (
	// The kind of logon CreateProcessWithLogonW performs for itself when it
	// starts a sandbox, so a token built this way is the token a run gets and
	// not a near relation of it. A network logon would be cheaper and would
	// carry a different set of identities.
	logonInteractive = 2
	logonProvider    = 0
	// The machine's own account database, not the domain the caller happens
	// to be logged into -- the same reason proc.RunAsAccount passes it.
	thisMachine = "."
)

// OfSandbox builds, from outside a run, the token a run gets inside one.
//
// There is one way to do that and this is it: log the sandbox's account on,
// and cut that token down exactly as the stub cuts its own down. Everything
// short of it is a model, and the model this replaces was wrong in a way that
// showed. Restricted hands back a restricted copy of the *caller's* token, so
// the first of the two access checks reads the caller's memberships and
// neither check ever sees the sandbox account's own identifier. On the
// sandbox's own profile -- whose permissions name that identifier and little
// else, and which every run writes to -- it answered "refused".
//
// It costs a logon, which is why callers that have more than one question to
// ask should keep the token rather than build it again.
//
// Nothing is started under it, and the password is not kept: it reaches
// Windows and is cleared in the same call.
func OfSandbox(accountName, password, sandboxGroup string) (syscall.Token, error) {
	caller, err := sid.CurrentUser()
	if err != nil {
		return 0, err
	}
	logged, err := logOn(accountName, password)
	if err != nil {
		return 0, err
	}
	defer logged.Close()
	// The read group of whoever is asking, the same one Restricted works out,
	// because the account joined the read group of whoever built it -- and
	// that is this person, since nobody else can open the sealed password
	// that got us this far.
	return restrict(logged, sandboxGroup, group.ReadGroupFor(caller), true)
}

// logOn asks Windows for the account's own token.
//
// It needs no privilege of any kind. LogonUser with explicit credentials is
// its own authority: knowing the password is what it proves, which is why a
// sandbox's password is sealed to the account that made it rather than merely
// kept out of sight.
func logOn(name, password string) (syscall.Token, error) {
	secret, err := syscall.UTF16FromString(password)
	if err != nil {
		return 0, err
	}
	// The only copy this makes, gone the moment Windows is done reading it,
	// rather than left for the collector to hand back in a freed page.
	defer clear(secret)

	user, domain := w32.UTF16(name), w32.UTF16(thisMachine)
	var logged syscall.Token
	r, _, callErr := procLogonUser.Call(uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(&secret[0])), logonInteractive, logonProvider,
		uintptr(unsafe.Pointer(&logged)))
	// Each argument reaches the call as a plain number, which is not a
	// reference the collector can see.
	runtime.KeepAlive(user)
	runtime.KeepAlive(domain)
	runtime.KeepAlive(secret)
	if r == 0 {
		return 0, fmt.Errorf("logging %s on: %w", name, callErr)
	}
	return logged, nil
}
