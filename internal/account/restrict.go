// Keeping the account off doors CreateProcessWithLogonW never uses: the
// sign-in screen's account list, kept in the registry, and Remote Desktop,
// kept in the local security policy.
//
// SeDenyInteractiveLogonRight is deliberately not set here. Windows checks
// that right for any logon of type LOGON32_LOGON_INTERACTIVE, and
// CreateProcessWithLogonW performs exactly that kind of logon internally to
// start the sandboxed process -- it is not a console-only check. Denying it
// would not merely keep this account off the sign-in screen; it would break
// the one call this whole design depends on running unprivileged, on every
// run, which is a documented cost of the same call for service accounts
// that were never granted "log on locally" either. Hiding the account and
// denying Remote Desktop close every door that call does not use, without
// touching the one it does.

package account

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procRegCreateKeyEx = w32.Advapi32.NewProc("RegCreateKeyExW")
	procRegSetValueEx  = w32.Advapi32.NewProc("RegSetValueExW")
	procRegDeleteValue = w32.Advapi32.NewProc("RegDeleteValueW")
	procRegCloseKey    = w32.Advapi32.NewProc("RegCloseKey")
)

const (
	hkeyLocalMachine = 0x80000002
	keySetValue      = 0x0002
	regDword         = 4
	errFileNotFound  = 2

	// specialAccounts is the same key Windows itself uses to hide its own
	// built-in service accounts (DefaultAccount, WDAGUtilityAccount) from
	// the sign-in screen's account list. A value here named for an account,
	// set to 0, keeps that account off the list without touching what it
	// may or may not log on to.
	specialAccounts = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`
)

func openSpecialAccounts() (uintptr, error) {
	var key uintptr
	r, _, _ := procRegCreateKeyEx.Call(hkeyLocalMachine, uintptr(unsafe.Pointer(w32.UTF16(specialAccounts))),
		0, 0, 0, keySetValue, 0, uintptr(unsafe.Pointer(&key)), 0)
	if r != 0 {
		return 0, fmt.Errorf("opening SpecialAccounts\\UserList: error %d", r)
	}
	return key, nil
}

// HideFromSignIn keeps name off the sign-in screen's account list. Requires
// administrator rights: the key lives under HKEY_LOCAL_MACHINE.
func HideFromSignIn(name string) error {
	key, err := openSpecialAccounts()
	if err != nil {
		return err
	}
	defer procRegCloseKey.Call(key)
	var value uint32 // 0 hides the account; Windows documents no other value
	if r, _, _ := procRegSetValueEx.Call(key, uintptr(unsafe.Pointer(w32.UTF16(name))), 0, regDword,
		uintptr(unsafe.Pointer(&value)), 4); r != 0 {
		return fmt.Errorf("hiding %s from the sign-in screen: error %d", name, r)
	}
	return nil
}

// UnhideFromSignIn removes the entry HideFromSignIn made. A value that is
// not there is not an error: the account may have been made by a version of
// wuserbox that predates this entry, or by a removal that already took it.
func UnhideFromSignIn(name string) error {
	key, err := openSpecialAccounts()
	if err != nil {
		return err
	}
	defer procRegCloseKey.Call(key)
	if r, _, _ := procRegDeleteValue.Call(key, uintptr(unsafe.Pointer(w32.UTF16(name)))); r != 0 && r != errFileNotFound {
		return fmt.Errorf("un-hiding %s from the sign-in screen: error %d", name, r)
	}
	return nil
}

// LSA_UNICODE_STRING and LSA_OBJECT_ATTRIBUTES, the two structures every
// LSA policy call below needs.
type lsaUnicodeString struct {
	length        uint16
	maximumLength uint16
	buffer        *uint16
}

type lsaObjectAttributes struct {
	length                   uint32
	rootDirectory            uintptr
	objectName               uintptr
	attributes               uint32
	securityDescriptor       uintptr
	securityQualityOfService uintptr
}

var (
	procLsaOpenPolicy       = w32.Advapi32.NewProc("LsaOpenPolicy")
	procLsaClose            = w32.Advapi32.NewProc("LsaClose")
	procLsaAddAccountRights = w32.Advapi32.NewProc("LsaAddAccountRights")
)

// policyAllAccess is POLICY_ALL_ACCESS from ntsecapi.h. Administrator
// rights are already required to reach this call at all, so there is
// nothing to gain from asking for a narrower set and risking a mismatch
// with whichever specific right LsaAddAccountRights turns out to need.
const policyAllAccess = 0x000F0FFF

func lsaString(s string) (lsaUnicodeString, []uint16) {
	wide, _ := syscall.UTF16FromString(s)
	bytes := uint16((len(wide) - 1) * 2)
	return lsaUnicodeString{length: bytes, maximumLength: bytes + 2, buffer: &wide[0]}, wide
}

// DenyRemoteLogon denies the account permission to log on over Remote
// Desktop, via the local security policy rather than group membership: the
// default that keeps an ordinary account off Remote Desktop is that it was
// never added to the Remote Desktop Users group, which is a door left
// unopened rather than one closed, and this closes it. Requires
// administrator rights.
func DenyRemoteLogon(name string) error {
	value, err := sid.Lookup(name)
	if err != nil {
		return err
	}
	var attrs lsaObjectAttributes
	attrs.length = uint32(unsafe.Sizeof(attrs))
	var handle uintptr
	if r, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs)),
		policyAllAccess, uintptr(unsafe.Pointer(&handle))); r != 0 {
		return fmt.Errorf("opening the local security policy: NTSTATUS 0x%x", r)
	}
	defer procLsaClose.Call(handle)

	right, wide := lsaString("SeDenyRemoteInteractiveLogonRight")
	r, _, _ := procLsaAddAccountRights.Call(handle, uintptr(unsafe.Pointer(&value[0])),
		uintptr(unsafe.Pointer(&right)), 1)
	runtime.KeepAlive(wide)
	runtime.KeepAlive(value)
	if r != 0 {
		return fmt.Errorf("denying %s permission to log on over Remote Desktop: NTSTATUS 0x%x", name, r)
	}
	return nil
}
