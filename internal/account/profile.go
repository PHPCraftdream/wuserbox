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

// DeleteProfile removes the profile recorded for an account, identified by
// its SID text so that removal can still find it after the account itself is
// deleted -- which is why this is called while the account still resolves.
// An account that has no profile recorded at all has nothing to remove, and
// that is not an error. Requires administrator rights.
//
// Two ways, because there are two kinds of profile here. DeleteProfileW is
// the right call for one Windows made and may still have loaded, and it is
// tried first. It refuses the one wuserbox seeds itself: that entry is
// written with plain registry calls and points at a directory Windows never
// built, so the call that exists to undo Windows' own work finds nothing it
// recognizes. Measured on CI, where this runs with the administrator rights
// it needs and a local run skips -- it failed on every removal, which would
// have left `--rm` reporting a sandbox it had in fact removed as one still
// half there.
//
// So where it refuses and the record is still standing, the record is taken
// out the same way it was put in.
func DeleteProfile(accountSID string) error {
	if r, _, _ := procDeleteProfile.Call(uintptr(unsafe.Pointer(w32.UTF16(accountSID))), 0, 0); r != 0 {
		return nil
	}
	if !hasProfile(accountSID) {
		return nil
	}
	if r, _, _ := procRegDeleteKey.Call(hkeyLocalMachine,
		uintptr(unsafe.Pointer(w32.UTF16(profileList+accountSID)))); r != 0 && r != errFileNotFound {
		return fmt.Errorf("deleting the profile record for %s: error %d", accountSID, r)
	}
	return nil
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
