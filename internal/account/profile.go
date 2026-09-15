// The profile directory Windows makes the first time an account logs on --
// found and removed by the account's SID, which keeps meaning the same
// thing after the account itself is gone, rather than by its name.

package account

import (
	"fmt"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procDeleteProfile = w32.Userenv.NewProc("DeleteProfileW")
	procRegOpenKeyEx  = w32.Advapi32.NewProc("RegOpenKeyExW")
)

// profileList is where Windows records, per SID, where a profile it made
// was put.
const profileList = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`

// DeleteProfile removes the profile directory Windows made for an account,
// identified by its SID text so that removal can still find it after the
// account itself is deleted -- which is why this is called first, while the
// account still resolves, during removal. An account whose password was
// never used to log on has no profile to remove, and that is not an error:
// hasProfile tells the two cases apart, since DeleteProfileW itself reports
// both the same way. Requires administrator rights.
func DeleteProfile(accountSID string) error {
	if r, _, _ := procDeleteProfile.Call(uintptr(unsafe.Pointer(w32.UTF16(accountSID))), 0, 0); r != 0 {
		return nil
	}
	if !hasProfile(accountSID) {
		return nil
	}
	return fmt.Errorf("deleting the profile for %s: DeleteProfileW failed", accountSID)
}

// hasProfile reports whether Windows ever recorded a profile for a SID. It
// opens the key rather than creating it -- RegCreateKeyExW would otherwise
// leave behind exactly the record it was checking for -- so reading needs
// no particular rights and changes nothing either way.
func hasProfile(accountSID string) bool {
	var key uintptr
	r, _, _ := procRegOpenKeyEx.Call(hkeyLocalMachine,
		uintptr(unsafe.Pointer(w32.UTF16(profileList+accountSID))), 0, keyQueryValue,
		uintptr(unsafe.Pointer(&key)))
	if r != 0 {
		return false
	}
	procRegCloseKey.Call(key)
	return true
}

const keyQueryValue = 0x0001
